package pxta

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

// Redacted replaces every personal value in a redacted report.
const Redacted = "REDACTED"

// probeValues are what PXTA itself types into forms. They are the evidence
// in a report and nobody's data, so redaction keeps them.
var probeValues = []string{ProbeEmail, "pat", "probe", "pat probe", "+1 555 0100 123", "15550100123", "+15550100123", "5550100123"}

var probeSet = func() map[string]bool {
	m := map[string]bool{}
	for _, v := range probeValues {
		v = strings.ToLower(v)
		m[v] = true
		s := sha256.Sum256([]byte(v))
		h := md5.Sum([]byte(v))
		m[hex.EncodeToString(s[:])] = true
		m[hex.EncodeToString(h[:])] = true
	}
	return m
}()

func isProbe(v string) bool { return probeSet[strings.ToLower(strings.TrimSpace(v))] }

// shortLen: values shorter than this (a first name, a short user ID) only
// match as whole words, so "Tim" never cuts into "time" and "2026" into a
// date. Longer values (addresses, hashes, client IDs) match anywhere,
// because they turn up glued to other text inside encoded URLs.
const shortLen = 8

// Minimum lengths for values to count at all.
const (
	minName = 3
	minID   = 6
	minHash = 16
)

// redactor holds the personal values found in one audit.
type redactor struct {
	secrets map[string]bool // lower case
	re      *regexp.Regexp  // every secret in every encoding, case-insensitive
	longRe  *regexp.Regexp  // only the long ones: what the after-write scan looks for in raw files
}

// secretHeaders are request headers whose whole value is personal. PXTA
// records only Content-Type and Referer today; this is a backstop.
var secretHeaders = map[string]bool{"cookie": true, "authorization": true, "proxy-authorization": true, "x-csrf-token": true}

// personalRules are the leak rules whose values are someone's data. Search
// terms and sensitive page words describe the site and stay.
var personalRules = map[string]bool{RuleEmail: true, RuleEmailHash: true, RulePhone: true, RulePhoneHash: true,
	RuleName: true, RuleNameHash: true, RuleUserHash: true, RuleUserID: true}

// fixedFields are struct fields that hold PXTA's own vocabulary (codes,
// severities, passes, tracker IDs, rule names, timestamps). Redaction never
// touches them.
var fixedFields = map[string]bool{"Code": true, "Severity": true, "Pass": true, "Passes": true, "Tracker": true, "ID": true,
	"Rule": true, "Kind": true, "Source": true, "Method": true, "Type": true, "Target": true, "Phase": true, "Tool": true,
	"Version": true, "Catalog": true, "Platform": true, "Time": true, "HARSHA256": true, "Vendor": true, "Category": true,
	"PageWait": true, "Idle": true, "BannerWait": true}

func (rd *redactor) add(v string, minLen int) {
	v = strings.TrimSpace(v)
	if len(v) < minLen || strings.EqualFold(v, Redacted) || isProbe(v) {
		return
	}
	rd.secrets[strings.ToLower(v)] = true
}

func (rd *redactor) addEmail(e string) {
	e = strings.ToLower(e)
	if !isEmail(e) || isProbe(e) {
		return
	}
	rd.add(e, 3)
	s := sha256.Sum256([]byte(e))
	m := md5.Sum([]byte(e))
	rd.add(hex.EncodeToString(s[:]), minHash)
	rd.add(hex.EncodeToString(m[:]), minHash)
}

// emailsIn finds the addresses in s, plain or URL-encoded.
func emailsIn(s string) []string {
	var out []string
	for _, v := range []string{s, unescapeAll(s), html.UnescapeString(s)} {
		for _, m := range emailRe.FindAllString(v, -1) {
			if isEmail(m) {
				out = append(out, m)
			}
		}
	}
	return out
}

func pageMap(res *Result) map[string]string {
	pageOf := map[string]string{}
	for _, v := range res.Pages {
		u := v.FinalURL
		if u == "" || u == "about:blank" {
			u = v.URL
		}
		pageOf[fmt.Sprintf("%s/%d", v.Pass, v.Page)] = u
	}
	return pageOf
}

// newRedactor collects the personal values in a result and its requests.
// It can run before Analyze (then res has pages but no findings) or on a
// findings.json read back (findings but no requests).
func newRedactor(res *Result, reqs []Request, emails *Emails, cat *Catalog) *redactor {
	rd := &redactor{secrets: map[string]bool{}}
	// A copy: what the redactor learns must not change the audit's findings.
	known := emails
	emails = NewEmails()
	if known != nil {
		for _, e := range known.List() {
			emails.Add(e)
		}
	}
	for _, e := range res.Emails {
		emails.Add(e)
	}
	// Every address anywhere first, so hashes sent before the address
	// showed up are known when the requests are classified.
	walkStrings(reflect.ValueOf(res), func(s string) string {
		for _, e := range emailsIn(s) {
			emails.Add(e)
		}
		return s
	})
	for _, r := range reqs {
		for _, e := range emailsIn(r.URL + " " + r.Body) {
			emails.Add(e)
		}
	}
	for _, e := range emails.List() {
		rd.addEmail(e)
	}
	pageOf := pageMap(res)
	for _, r := range reqs {
		for k, v := range r.Headers {
			if secretHeaders[strings.ToLower(k)] {
				for _, part := range strings.Split(v, ";") {
					if i := strings.IndexByte(part, '='); i >= 0 {
						rd.add(part[i+1:], shortLen)
					}
				}
			}
		}
		page := pageOf[fmt.Sprintf("%s/%d", r.Pass, r.Page)]
		var ps []Param
		var leaks []Leak
		if cat != nil {
			if c := Classify(cat, r, page, emails); c != nil {
				ps, leaks = c.Params, c.Leaks
			}
		}
		if ps == nil {
			ps = DecodeRequest(r.URL, r.Body, r.ContentType)
			leaks = FindLeaks(ps, page, emails)
		}
		rd.leakValues(leaks)
		for _, p := range ps {
			rd.param(p)
		}
	}
	// Findings carry their leaks too (a findings.json read back has no
	// requests).
	if res.Analysis != nil {
		for _, f := range res.Findings {
			rd.leakValues(f.Evidence.Highlight)
			for _, p := range f.Evidence.Params {
				rd.param(p)
			}
		}
	}
	rd.compile()
	return rd
}

func (rd *redactor) leakValues(leaks []Leak) {
	for _, l := range leaks {
		if !personalRules[l.Rule] {
			continue
		}
		switch l.Rule {
		case RuleName:
			rd.add(l.Value, minName)
		case RuleUserID:
			rd.add(l.Value, minID)
		case RuleEmailHash, RulePhoneHash, RuleNameHash, RuleUserHash:
			rd.add(l.Value, minHash)
		default:
			rd.add(l.Value, 3)
		}
	}
}

// param adds a decoded parameter's value when its kind or its name says it
// is about a person. Phone numbers and names count by their field name
// whatever kind the catalog gave the field: a tag that expects a hash can
// still be sent the plain number.
func (rd *redactor) param(p Param) {
	switch p.Kind {
	case KindClientID, KindUserID:
		rd.add(p.Value, minID)
	case KindEmailHash, KindPhoneHash, KindNameHash, KindUserHash:
		rd.add(p.Value, minHash)
	}
	lk := lastKeyPart(p.Key)
	uv := strings.TrimSpace(unescapeAll(p.Value))
	if phoneKeys[lk] && phoneRe.MatchString(uv) {
		rd.add(uv, 6)
		rd.add(p.Value, 6)
	}
	if nameKeys[lk] && len([]rune(uv)) >= minName && !strings.ContainsAny(uv, "0123456789@") {
		rd.add(uv, minName)
	}
}

// forms lists the ways a value can be written in a URL, a body or a report.
func forms(s string) []string {
	j, _ := json.Marshal(s)
	js := string(j[1 : len(j)-1])
	set := map[string]bool{}
	for _, f := range []string{s, url.QueryEscape(s), url.PathEscape(s), url.QueryEscape(url.QueryEscape(s)),
		js, html.EscapeString(s), strings.ReplaceAll(url.QueryEscape(s), "+", "%20")} {
		if f != "" {
			set[f] = true
		}
	}
	var l []string
	for f := range set {
		l = append(l, f)
	}
	return l
}

func alternation(alts []string) *regexp.Regexp {
	if len(alts) == 0 {
		return nil
	}
	// Longest first: at a given position the longest form wins.
	sort.Slice(alts, func(i, j int) bool {
		if len(alts[i]) != len(alts[j]) {
			return len(alts[i]) > len(alts[j])
		}
		return alts[i] < alts[j]
	})
	q := make([]string, len(alts))
	for i, a := range alts {
		q[i] = regexp.QuoteMeta(a)
	}
	return regexp.MustCompile("(?i)" + strings.Join(q, "|"))
}

func (rd *redactor) compile() {
	var all, long []string
	for s := range rd.secrets {
		for _, f := range forms(s) {
			all = append(all, f)
			if len(s) >= shortLen {
				long = append(long, f)
			}
		}
	}
	rd.re = alternation(all)
	rd.longRe = alternation(long)
}

func isWordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

// bounded reports whether s[i:j] stands alone: no letter or digit right
// before or after it.
func bounded(s string, i, j int) bool {
	return (i == 0 || !isWordByte(s[i-1])) && (j == len(s) || !isWordByte(s[j]))
}

// matches returns the spans of secrets in s: long values anywhere, short
// ones only as whole words.
func (rd *redactor) matches(s string) [][]int {
	if rd.re == nil {
		return nil
	}
	var out [][]int
	for _, m := range rd.re.FindAllStringIndex(s, -1) {
		if m[1]-m[0] < shortLen && !bounded(s, m[0], m[1]) {
			continue
		}
		out = append(out, m)
	}
	return out
}

// leaks reports whether a decoded value still carries a personal value.
func (rd *redactor) leaks(v string) bool {
	if len(rd.matches(v)) > 0 {
		return true
	}
	for _, e := range emailsIn(v) {
		if !isProbe(e) {
			return true
		}
	}
	return false
}

// text replaces the secrets in any form inside s, in one pass.
func (rd *redactor) text(s string) string {
	if ms := rd.matches(s); len(ms) > 0 {
		var b strings.Builder
		last := 0
		for _, m := range ms {
			b.WriteString(s[last:m[0]])
			b.WriteString(Redacted)
			last = m[1]
		}
		b.WriteString(s[last:])
		s = b.String()
	}
	// Addresses nobody listed (on a page, in a title) go too.
	return emailRe.ReplaceAllStringFunc(s, func(m string) string {
		if isEmail(m) && !isProbe(m) {
			return Redacted
		}
		return m
	})
}

// opaque redacts a value that hides a personal value in an encoding text
// replacement can't see into (base64, JSON inside a parameter).
func (rd *redactor) opaque(s string) string {
	if len(s) < 12 || strings.ContainsAny(s, " \n") {
		return s
	}
	for _, p := range DecodeRequest("https://x.invalid/?v="+url.QueryEscape(s), "", "") {
		if rd.leaks(p.Value) {
			return Redacted
		}
	}
	return s
}

// pairs redacts a query string or form body pair by pair, so a value that
// carries personal data in a form text replacement can't reach (base64,
// JSON inside a parameter) goes whole.
func (rd *redactor) pairs(q string) string {
	if q == "" {
		return q
	}
	parts := strings.Split(q, "&")
	for i, part := range parts {
		k, v, hasV := strings.Cut(part, "=")
		if !hasV {
			parts[i] = rd.text(part)
			continue
		}
		dirty := false
		for _, p := range DecodeRequest("https://x.invalid/?"+part, "", "") {
			if rd.leaks(p.Value) {
				dirty = true
				break
			}
		}
		if dirty {
			v = Redacted
		} else {
			v = rd.text(v)
		}
		parts[i] = rd.text(k) + "=" + v
	}
	return strings.Join(parts, "&")
}

// url redacts a URL or a page path: known values first, then the query pair
// by pair and each path segment for what only decoding shows.
func (rd *redactor) url(s string) string {
	s = rd.text(s)
	base, frag, hasFrag := strings.Cut(s, "#")
	pth, q, hasQ := strings.Cut(base, "?")
	scheme := ""
	if i := strings.Index(pth, "://"); i >= 0 {
		// Keep scheme and host out of the segment pass.
		rest := pth[i+3:]
		j := strings.IndexByte(rest, '/')
		if j < 0 {
			j = len(rest)
		}
		scheme, pth = pth[:i+3]+rest[:j], rest[j:]
	}
	segs := strings.Split(pth, "/")
	for i, seg := range segs {
		segs[i] = rd.opaque(seg)
	}
	out := scheme + strings.Join(segs, "/")
	if hasQ {
		out += "?" + rd.pairs(q)
	}
	if hasFrag {
		out += "#" + rd.text(frag)
	}
	return out
}

// body redacts a request body; when something is still readable after
// that, the body goes whole.
func (rd *redactor) body(body, ctype string) string {
	if body == "" {
		return body
	}
	out := rd.text(body)
	if strings.Contains(strings.ToLower(ctype), "x-www-form-urlencoded") || looksLikeForm(out) {
		out = rd.pairs(out)
	}
	for _, p := range DecodeRequest("https://x.invalid/", out, ctype) {
		if rd.leaks(p.Value) {
			return fmt.Sprintf("%s (a %d-byte body that held personal data)", Redacted, len(body))
		}
	}
	return out
}

var formRe = regexp.MustCompile(`^[A-Za-z0-9_.\-\[\]%]+=[^&\s]*(&[A-Za-z0-9_.\-\[\]%]+=[^&\s]*)*$`)

func looksLikeForm(s string) bool { return len(s) < 1<<20 && formRe.MatchString(s) }

// looksLikeURL tells addresses and page paths from sentences.
func looksLikeURL(s string) bool {
	if strings.ContainsAny(s, " \n") {
		return false
	}
	return strings.HasPrefix(s, "/") || strings.Contains(s, "://")
}

// field redacts one free-text field.
func (rd *redactor) field(s string) string {
	s = rd.text(s)
	if looksLikeURL(s) {
		return rd.url(s)
	}
	// A sentence can quote a page address; redact the addresses in it too.
	words := strings.Split(s, " ")
	for i, w := range words {
		if strings.HasPrefix(w, "/") || strings.Contains(w, "://") {
			words[i] = rd.url(w)
		}
	}
	return rd.opaque(strings.Join(words, " "))
}

// apply redacts the result in place, and the requests it will write.
func (rd *redactor) apply(res *Result, reqs []Request) {
	walkStrings(reflect.ValueOf(res), rd.field)
	if res.Analysis != nil {
		for _, f := range res.Findings {
			f.Evidence.Body = rd.body(f.Evidence.Body, "")
		}
	}
	for i := range reqs {
		r := &reqs[i]
		r.Body = rd.body(r.Body, r.ContentType)
		r.URL = rd.url(r.URL)
		for k, v := range r.Headers {
			if secretHeaders[strings.ToLower(k)] {
				r.Headers[k] = Redacted
			} else {
				r.Headers[k] = rd.field(v)
			}
		}
	}
	res.Redacted = true
}

// walkStrings calls fn on every settable string reachable from v, except
// the fixed fields, and stores what it returns. Map keys are left alone
// (passes and severities).
func walkStrings(v reflect.Value, fn func(string) string) {
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface:
		if !v.IsNil() {
			walkStrings(v.Elem(), fn)
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := t.Field(i)
			if f.IsExported() && (f.Anonymous || !fixedFields[f.Name]) {
				walkStrings(v.Field(i), fn)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			walkStrings(v.Index(i), fn)
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			e := v.MapIndex(k)
			switch e.Kind() {
			case reflect.String:
				v.SetMapIndex(k, reflect.ValueOf(fn(e.String())).Convert(e.Type()))
			case reflect.Slice:
				cp := reflect.MakeSlice(e.Type(), e.Len(), e.Len())
				reflect.Copy(cp, e)
				walkStrings(cp, fn)
				v.SetMapIndex(k, cp)
			}
		}
	case reflect.String:
		if v.CanSet() {
			v.SetString(fn(v.String()))
		}
	}
}

// VerifyRedacted checks the report files in dir after a redacted audit.
// It does nothing for an audit that wasn't redacted.
func (r *Result) VerifyRedacted(dir string) error {
	if !r.Redacted || r.redactor == nil {
		return nil
	}
	return r.redactor.VerifyRedacted(dir)
}

// Redact takes the personal values out of an audit result, its requests
// and its findings, in place. emails may be nil (a findings.json read
// back), and so may cat.
func Redact(res *Result, emails *Emails, cat *Catalog) *redactor {
	rd := newRedactor(res, res.requests, emails, cat)
	rd.apply(res, res.requests)
	res.redactor = rd
	return rd
}

// VerifyRedacted reads the files an audit wrote and fails if a personal
// value is still in them. Raw file text is searched for the long values
// (addresses, hashes, IDs) in every form, and for any email address but
// the probe. Short values (first names, short IDs) can't be told from
// ordinary words in raw text, so they are checked field by field: every
// string value in findings.json, and every decoded parameter in
// requests.har.
func (rd *redactor) VerifyRedacted(dir string) error {
	for _, name := range []string{"findings.json", "report.html", "requests.har", "check.json"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if os.IsNotExist(err) && name == "check.json" {
			continue
		}
		if err != nil {
			return err
		}
		s := string(b)
		for _, v := range []string{s, html.UnescapeString(s), unescapeAll(s), unescapeAll(html.UnescapeString(s))} {
			if rd.longRe != nil {
				if m := rd.longRe.FindString(v); m != "" {
					return fmt.Errorf("redaction check: %s still holds a personal value (%d characters)", name, len(m))
				}
			}
			for _, m := range emailRe.FindAllString(v, -1) {
				if isEmail(m) && !isProbe(m) {
					return fmt.Errorf("redaction check: %s still holds an email address", name)
				}
			}
		}
		switch name {
		case "findings.json", "check.json":
			if err := rd.verifyJSON(name, b); err != nil {
				return err
			}
		case "requests.har":
			if err := rd.verifyHAR(b); err != nil {
				return err
			}
		}
	}
	return nil
}

// verifyJSON checks every string value (never the keys, never PXTA's own
// codes) for a short value standing as a word.
func (rd *redactor) verifyJSON(name string, b []byte) error {
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("redaction check: %s: %w", name, err)
	}
	var bad error
	var walk func(key string, v any)
	walk = func(key string, v any) {
		if bad != nil {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			for k, e := range t {
				walk(k, e)
			}
		case []any:
			for _, e := range t {
				walk(key, e)
			}
		case string:
			if fixedJSONKeys[key] {
				return
			}
			for _, u := range []string{t, unescapeAll(t)} {
				if len(rd.matches(u)) > 0 {
					bad = fmt.Errorf("redaction check: %s still holds a personal value in %q", name, key)
					return
				}
			}
		}
	}
	walk("", doc)
	return bad
}

// fixedJSONKeys are the JSON names of fixedFields.
var fixedJSONKeys = map[string]bool{"code": true, "severity": true, "pass": true, "passes": true, "tracker": true, "id": true,
	"rule": true, "kind": true, "source": true, "method": true, "type": true, "target": true, "phase": true, "tool": true,
	"version": true, "catalog": true, "platform": true, "time": true, "har_sha256": true, "vendor": true, "category": true,
	"started": true, "finished": true, "page_wait": true, "idle": true, "banner_wait": true, "fail_on": true}

// verifyHAR decodes every recorded request the way the audit does (base64,
// JSON, nested parameters, path segments) and fails on a personal value in
// any of them.
func (rd *redactor) verifyHAR(b []byte) error {
	var h harLog
	if err := json.Unmarshal(b, &h); err != nil {
		return fmt.Errorf("redaction check: requests.har: %w", err)
	}
	for i, e := range h.Log.Entries {
		body, ctype := "", ""
		if e.Request.PostData != nil {
			body, ctype = e.Request.PostData.Text, e.Request.PostData.MimeType
		}
		ps := DecodeRequest(e.Request.URL, body, ctype)
		if u, err := url.Parse(e.Request.URL); err == nil {
			for _, seg := range strings.Split(u.EscapedPath(), "/") {
				if seg != "" {
					ps = append(ps, DecodeRequest("https://x.invalid/?v="+seg, "", "")...)
				}
			}
		}
		for _, p := range ps {
			if rd.leaks(p.Value) {
				return fmt.Errorf("redaction check: requests.har entry %d still carries a personal value", i+1)
			}
		}
	}
	return nil
}
