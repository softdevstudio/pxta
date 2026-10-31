package pxta

import (
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
)

// Passes. "none" is a visit where the consent banner was left unanswered;
// "nobanner" is the only pass when a site shows no banner at all.
const (
	PassNone     = "none"
	PassReject   = "reject"
	PassAccept   = "accept"
	PassNoBanner = "nobanner"
)

// Severities, highest first.
const (
	SevHigh   = "high"
	SevMedium = "medium"
	SevLow    = "low"
	SevInfo   = "info"
)

var sevRank = map[string]int{SevHigh: 4, SevMedium: 3, SevLow: 2, SevInfo: 1}

// Finding codes. They are a public interface: never rename one.
const (
	CodeTrackerBeforeConsent = "tracker-before-consent"
	CodeTrackerAfterReject   = "tracker-after-reject"
	CodePersonalData         = "personal-data"
	CodeSensitivePage        = "sensitive-page"
	CodeSearchTerm           = "search-term"
	CodeConsentModeGranted   = "consent-mode-granted"
	CodeConsentModeMismatch  = "consent-mode-mismatch"
	CodeBannerNotHandled     = "banner-not-handled"
	CodeTrackerPresent       = "tracker-present"
)

// Evidence is the request behind a finding.
type Evidence struct {
	URL         string  `json:"url"`
	Method      string  `json:"method"`
	Time        string  `json:"time"`
	Type        string  `json:"type,omitempty"`
	Target      string  `json:"target,omitempty"`
	Phase       string  `json:"phase,omitempty"`
	Params      []Param `json:"params"`
	Highlight   []Leak  `json:"leaks,omitempty"`
	ConsentMode string  `json:"consent_mode,omitempty"`
	Body        string  `json:"body,omitempty"`
}

// Finding is one piece of evidence-backed reporting.
type Finding struct {
	Code     string   `json:"code"`
	Severity string   `json:"severity"`
	Pass     string   `json:"pass"`
	Page     string   `json:"page"`
	Tracker  string   `json:"tracker"`
	Name     string   `json:"tracker_name"`
	Sentence string   `json:"sentence"`
	Count    int      `json:"count"`
	Evidence Evidence `json:"evidence"`
	Repro    string   `json:"reproduce,omitempty"`
	key      string
}

// TrackerUse is one row of the tracker inventory.
type TrackerUse struct {
	ID       string              `json:"id"`
	Name     string              `json:"name"`
	Vendor   string              `json:"vendor"`
	Loaded   map[string][]string `json:"loaded_on"` // pass -> pages where its script loaded
	Fired    map[string][]string `json:"fired_on"`  // pass -> pages where it sent data
	Requests map[string]int      `json:"requests"`  // pass -> collection requests
}

// Classified is a recorded request with what PXTA made of it.
type Classified struct {
	Req     Request
	Tracker *Tracker // nil for an unclassified beacon
	Host    string
	Collect bool
	Params  []Param
	Leaks   []Leak
	GCS     string
}

// Analysis is everything derived from the recorded requests.
type Analysis struct {
	Findings []*Finding     `json:"findings"`
	Trackers []TrackerUse   `json:"trackers"`
	Counts   map[string]int `json:"counts"`
}

func whenPhrase(pass string) string {
	switch pass {
	case PassNone:
		return "before the consent banner was answered"
	case PassReject:
		return "after the visitor rejected tracking"
	case PassAccept:
		return "after the visitor accepted tracking"
	default:
		return "on a site that shows no consent banner"
	}
}

func trackerPhrase(name string, t *Tracker) string {
	if t == nil {
		return "a request to " + name
	}
	if strings.HasPrefix(name, "Google Analytics") {
		return name
	}
	return "the " + name
}

// pagePath shows a page as its path and query, shortened for sentences.
func pagePath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	if d, err := url.PathUnescape(p); err == nil {
		p = d
	}
	if len([]rune(p)) > 90 {
		p = string([]rune(p)[:87]) + "..."
	}
	return p
}

func isThirdParty(reqURL, pageURL string) (host string, third bool) {
	u, err := url.Parse(reqURL)
	if err != nil {
		return "", false
	}
	pu, err := url.Parse(pageURL)
	if err != nil {
		return u.Hostname(), false
	}
	return u.Hostname(), registrableDomain(u.Hostname()) != registrableDomain(pu.Hostname())
}

var staticExt = map[string]bool{".js": true, ".mjs": true, ".css": true, ".woff": true, ".woff2": true, ".ttf": true, ".otf": true,
	".svg": true, ".map": true, ".mp4": true, ".webm": true, ".mp3": true, ".wasm": true}

// looksLikeBeacon picks unclassified third-party requests that send data:
// sendBeacon and ping, POSTs, and requests with three or more parameters.
func looksLikeBeacon(r Request, ps []Param) bool {
	u, err := url.Parse(r.URL)
	if err != nil {
		return false
	}
	if staticExt[strings.ToLower(path.Ext(u.Path))] {
		return false
	}
	switch r.Type {
	case "Ping", "CSPViolationReport":
		return true
	case "Document", "Stylesheet", "Font", "Media", "Manifest":
		return false
	}
	if r.Method == "POST" && r.Body != "" {
		return true
	}
	n := 0
	for _, p := range ps {
		if p.Source == "query" {
			n++
		}
	}
	return n >= 3
}

// Classify decodes a request and applies the rules. pageURL is the page it
// was recorded on.
func Classify(cat *Catalog, r Request, pageURL string, emails *Emails) *Classified {
	c := &Classified{Req: r}
	t, collect := cat.Match(r.URL)
	host, third := isThirdParty(r.URL, pageURL)
	c.Host = host
	if t == nil {
		if !third {
			return nil
		}
		ps := DecodeRequest(r.URL, r.Body, r.ContentType)
		leaks := FindLeaks(ps, pageURL, emails)
		// Any third-party request that carries personal data counts, whatever
		// its shape; otherwise only beacon-like ones do.
		personal := false
		for _, l := range leaks {
			if l.Rule != RuleSensitive {
				personal = true
			}
		}
		if !personal && !looksLikeBeacon(r, ps) {
			return nil
		}
		c.Collect, c.Params, c.Leaks = true, ps, leaks
		return c
	}
	c.Tracker, c.Collect = t, collect
	if !collect {
		return c
	}
	c.Params = DecodeRequest(r.URL, r.Body, r.ContentType)
	Describe(t, c.Params)
	c.Leaks = FindLeaks(c.Params, pageURL, emails)
	for _, p := range c.Params {
		if baseKey(p.Key) == "gcs" {
			c.GCS = p.Value
		}
	}
	return c
}

func eventName(ps []Param) string {
	for _, p := range ps {
		if p.Kind == KindEvent && p.Value != "" && len(p.Value) < 60 && !strings.ContainsAny(p.Value, "[{") {
			return p.Value
		}
	}
	return ""
}

func severityFor(code, pass string) string {
	switch code {
	case CodeTrackerBeforeConsent, CodeTrackerAfterReject:
		return SevMedium
	case CodePersonalData, CodeSensitivePage, CodeSearchTerm:
		if pass == PassAccept {
			return SevLow
		}
		return SevHigh
	case CodeConsentModeGranted:
		if pass == PassReject {
			return SevHigh
		}
		return SevMedium
	case CodeConsentModeMismatch:
		if pass == PassAccept {
			return SevLow
		}
		return SevHigh
	}
	return SevInfo
}

// Analyze turns recorded requests into findings and the tracker inventory.
// visits gives each page's address per pass.
func Analyze(cat *Catalog, visits []Visit, reqs []Request, emails *Emails, reproBase string) *Analysis {
	return analyze(cat, visits, reqs, emails, reproBase, nil)
}

// analyze is Analyze with a hook that rewrites page addresses before they
// are shortened for sentences: a redacted audit takes the personal values
// out first, so no cut-off piece of one is left behind.
func analyze(cat *Catalog, visits []Visit, reqs []Request, emails *Emails, reproBase string, pageFn func(string) string) *Analysis {
	shorten := pagePath
	if pageFn != nil {
		shorten = func(raw string) string { return pagePath(pageFn(raw)) }
	}
	pageOf := map[string]string{}
	for _, v := range visits {
		u := v.FinalURL
		if u == "" || u == "about:blank" {
			u = v.URL
		}
		pageOf[fmt.Sprintf("%s/%d", v.Pass, v.Page)] = u
	}
	a := &Analysis{Counts: map[string]int{}}
	byKey := map[string]*Finding{}
	use := map[string]*TrackerUse{}
	addUse := func(t *Tracker, id, name, vendor, pass, page string, fired bool) {
		u := use[id]
		if u == nil {
			u = &TrackerUse{ID: id, Name: name, Vendor: vendor, Loaded: map[string][]string{}, Fired: map[string][]string{}, Requests: map[string]int{}}
			use[id] = u
		}
		if fired {
			u.Requests[pass]++
			if !contains(u.Fired[pass], page) {
				u.Fired[pass] = append(u.Fired[pass], page)
			}
		} else if !contains(u.Loaded[pass], page) {
			u.Loaded[pass] = append(u.Loaded[pass], page)
		}
	}
	add := func(f *Finding) {
		if old := byKey[f.key]; old != nil {
			old.Count++
			return
		}
		f.Count = 1
		f.Severity = severityFor(f.Code, f.Pass)
		byKey[f.key] = f
		a.Findings = append(a.Findings, f)
	}
	// Two sweeps: the first collects every email address seen in any
	// request, so a hash sent before the address showed up is still matched.
	for _, r := range reqs {
		page := pageOf[fmt.Sprintf("%s/%d", r.Pass, r.Page)]
		Classify(cat, r, page, emails)
	}
	for _, r := range reqs {
		page := pageOf[fmt.Sprintf("%s/%d", r.Pass, r.Page)]
		c := Classify(cat, r, page, emails)
		if c == nil {
			continue
		}
		id, name, vendor := "", c.Host, ""
		if c.Tracker != nil {
			id, name, vendor = c.Tracker.ID, c.Tracker.Name, c.Tracker.Vendor
		} else {
			id, name, vendor = "unclassified:"+c.Host, c.Host, "unclassified"
		}
		pp := shorten(page)
		// Findings are told apart by the real page, so redaction (which can
		// make two pages read the same) never merges them.
		rawPP := pagePath(page)
		addUse(c.Tracker, id, name, vendor, r.Pass, pp, c.Collect)
		if !c.Collect {
			continue
		}
		ev := Evidence{URL: r.URL, Method: r.Method, Time: r.Time.Format("2006-01-02T15:04:05.000Z"), Type: r.Type, Target: r.Target,
			Phase: r.Phase, Params: c.Params, Body: r.Body}
		if c.GCS != "" {
			if ad, an, ok := ConsentModeState(c.GCS); ok {
				ev.ConsentMode = fmt.Sprintf("%s: ad_storage %s, analytics_storage %s", c.GCS, ad, an)
			}
		}
		tp := trackerPhrase(name, c.Tracker)
		when := whenPhrase(r.Pass)
		repro := ""
		if reproBase != "" {
			repro = reproBase + " " + shellQuote(page) + " --pages 1"
		}
		mk := func(code, what, keyExtra string, leaks []Leak) *Finding {
			s := fmt.Sprintf("On %s, %s sent %s %s.", pp, tp, what, when)
			e := ev
			e.Highlight = leaks
			return &Finding{Code: code, Pass: r.Pass, Page: pp, Tracker: id, Name: name, Sentence: s, Evidence: e, Repro: repro,
				key: code + "|" + r.Pass + "|" + rawPP + "|" + id + "|" + keyExtra}
		}
		if r.Pass != PassAccept {
			code := CodeTrackerBeforeConsent
			if r.Pass == PassReject {
				code = CodeTrackerAfterReject
			}
			if c.Tracker != nil {
				what := "a request"
				if en := eventName(c.Params); en != "" {
					what = "a " + en + " event"
				}
				add(mk(code, what, "", nil))
			}
		}
		for _, l := range c.Leaks {
			code := CodePersonalData
			switch l.Rule {
			case RuleSensitive:
				code = CodeSensitivePage
			case RuleSearch:
				code = CodeSearchTerm
			}
			what := l.What
			if l.InURL && code == CodePersonalData {
				what += " inside the page address"
			}
			if code == CodeSensitivePage {
				what += " (" + shorten(l.Value) + ")"
			}
			add(mk(code, what, l.Rule+"|"+strings.ToLower(l.Value), []Leak{l}))
		}
		if c.GCS != "" {
			ad, an, ok := ConsentModeState(c.GCS)
			if ok && (r.Pass == PassNone || r.Pass == PassReject) && (ad == "granted" || an == "granted") {
				f := mk(CodeConsentModeGranted, "", "", nil)
				f.Sentence = fmt.Sprintf("On %s, %s reported Google Consent Mode as granted (%s: ad_storage %s, analytics_storage %s) %s.", pp, tp, c.GCS, ad, an, when)
				add(f)
			}
			if ok && (ad == "denied" || an == "denied") {
				var ids []Leak
				for _, l := range c.Leaks {
					if l.Rule != RuleSearch && l.Rule != RuleSensitive {
						ids = append(ids, l)
					}
				}
				if len(ids) > 0 {
					f := mk(CodeConsentModeMismatch, "", "", ids)
					f.Sentence = fmt.Sprintf("On %s, %s reported Google Consent Mode as denied (%s) but still sent %s, %s.", pp, tp, c.GCS, ids[0].What, when)
					add(f)
				}
			}
		}
	}
	for _, u := range use {
		a.Trackers = append(a.Trackers, *u)
		for pass, pages := range u.Fired {
			_ = pages
			f := &Finding{Code: CodeTrackerPresent, Pass: pass, Tracker: u.ID, Name: u.Name, Count: u.Requests[pass], Severity: SevInfo,
				Sentence: fmt.Sprintf("%s sent data from %d page%s %s.", capitalize(trackerPhrase(u.Name, trackerOrNil(cat, u.ID))), len(u.Fired[pass]), plural(len(u.Fired[pass])), whenPhrase(pass))}
			a.Findings = append(a.Findings, f)
		}
	}
	sort.Slice(a.Trackers, func(i, j int) bool { return a.Trackers[i].Name < a.Trackers[j].Name })
	sortFindings(a.Findings)
	for _, f := range a.Findings {
		a.Counts[f.Severity]++
	}
	return a
}

func trackerOrNil(cat *Catalog, id string) *Tracker {
	for _, t := range cat.Trackers {
		if t.ID == id {
			return t
		}
	}
	return nil
}

var passOrder = map[string]int{PassNone: 0, PassNoBanner: 0, PassReject: 1, PassAccept: 2}

var codeOrder = map[string]int{CodePersonalData: 0, CodeSensitivePage: 1, CodeSearchTerm: 2, CodeConsentModeGranted: 3,
	CodeConsentModeMismatch: 4, CodeTrackerAfterReject: 5, CodeTrackerBeforeConsent: 6, CodeBannerNotHandled: 7, CodeTrackerPresent: 8}

func sortFindings(fs []*Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if sevRank[a.Severity] != sevRank[b.Severity] {
			return sevRank[a.Severity] > sevRank[b.Severity]
		}
		if codeOrder[a.Code] != codeOrder[b.Code] {
			return codeOrder[a.Code] < codeOrder[b.Code]
		}
		if passOrder[a.Pass] != passOrder[b.Pass] {
			return passOrder[a.Pass] < passOrder[b.Pass]
		}
		if a.Page != b.Page {
			return a.Page < b.Page
		}
		return a.Name < b.Name
	})
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func shellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:=", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
