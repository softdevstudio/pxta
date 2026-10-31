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

// redactor holds the personal values found in one audit.
type redactor struct {
	secrets map[string]bool // lower case
	re      *regexp.Regexp  // every secret in every encoding, case-insensitive
}

// secretHeaders are request headers whose whole value is personal.
var secretHeaders = map[string]bool{"cookie": true, "authorization": true, "proxy-authorization": true, "x-csrf-token": true}

// personalRules are the leak rules whose values are someone's data. Search
// terms and sensitive page words describe the site and stay.
var personalRules = map[string]bool{RuleEmail: true, RuleEmailHash: true, RulePhone: true, RulePhoneHash: true,
	RuleName: true, RuleNameHash: true, RuleUserHash: true, RuleUserID: true}

func (rd *redactor) add(v string, minLen int) {
	v = strings.TrimSpace(v)
	if len(v) < minLen || v == Redacted || isProbe(v) {
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
	rd.add(hex.EncodeToString(s[:]), 3)
	rd.add(hex.EncodeToString(m[:]), 3)
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

// newRedactor collects the personal values in a result and its requests.
func newRedactor(res *Result, reqs []Request, emails *Emails, cat *Catalog) *redactor {
	rd := &redactor{secrets: map[string]bool{}}
	if emails != nil {
		for _, e := range emails.List() {
			rd.addEmail(e)
		}
	}
	for _, e := range res.Emails {
		rd.addEmail(e)
	}
	walkStrings(reflect.ValueOf(res), func(s string) string {
		for _, e := range emailsIn(s) {
			rd.addEmail(e)
		}
		return s
	})
	pageOf := map[string]string{}
	for _, v := range res.Pages {
		u := v.FinalURL
		if u == "" || u == "about:blank" {
			u = v.URL
		}
		pageOf[fmt.Sprintf("%s/%d", v.Pass, v.Page)] = u
	}
	if emails == nil {
		emails = NewEmails()
		for _, e := range res.Emails {
			emails.Add(e)
		}
	}
	for _, r := range reqs {
		for _, e := range emailsIn(r.URL + " " + r.Body) {
			rd.addEmail(e)
		}
		for k, v := range r.Headers {
			if secretHeaders[strings.ToLower(k)] {
				// Cookie values one by one, so they're found inside URLs too.
				for _, part := range strings.Split(v, ";") {
					if i := strings.IndexByte(part, '='); i >= 0 {
						rd.add(part[i+1:], 8)
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
		for _, l := range leaks {
			if personalRules[l.Rule] {
				min := 3
				if l.Rule == RuleName {
					min = 2
				}
				rd.add(l.Value, min)
			}
		}
		for _, p := range ps {
			rd.param(p)
		}
	}
	// Findings carry their leaks too (a findings.json read back has no
	// requests).
	if res.Analysis != nil {
		for _, f := range res.Findings {
			for _, l := range f.Evidence.Highlight {
				if personalRules[l.Rule] {
					rd.add(l.Value, 2)
				}
			}
			for _, p := range f.Evidence.Params {
				rd.param(p)
			}
		}
	}
	rd.compile()
	return rd
}

// param adds a decoded parameter's value when its kind or its name says it
// is about a person. Phone numbers and names count by their field name
// whatever kind the catalog gave the field: a tag that expects a hash can
// still be sent the plain number.
func (rd *redactor) param(p Param) {
	switch p.Kind {
	case KindClientID, KindUserID:
		rd.add(p.Value, 6)
	case KindEmailHash, KindPhoneHash, KindNameHash, KindUserHash:
		rd.add(p.Value, 8)
	}
	lk := lastKeyPart(p.Key)
	uv := strings.TrimSpace(unescapeAll(p.Value))
	if phoneKeys[lk] && phoneRe.MatchString(uv) {
		rd.add(uv, 6)
		rd.add(p.Value, 6)
	}
	if nameKeys[lk] && len([]rune(uv)) >= 2 && !strings.ContainsAny(uv, "0123456789@") {
		rd.add(uv, 2)
	}
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

func (rd *redactor) compile() {
	var alts []string
	for s := range rd.secrets {
		for _, f := range forms(s) {
			alts = append(alts, regexp.QuoteMeta(f))
		}
	}
	if len(alts) == 0 {
		return
	}
	// Longest first, so a value inside another is not cut out of it first.
	sort.Slice(alts, func(i, j int) bool {
		if len(alts[i]) != len(alts[j]) {
			return len(alts[i]) > len(alts[j])
		}
		return alts[i] < alts[j]
	})
	rd.re = regexp.MustCompile("(?i)" + strings.Join(alts, "|"))
}

// leaks reports whether a decoded value still carries a personal value.
func (rd *redactor) leaks(v string) bool {
	low := strings.ToLower(v)
	for s := range rd.secrets {
		if strings.Contains(low, s) {
			return true
		}
	}
	for _, e := range emailsIn(v) {
		if !isProbe(e) {
			return true
		}
	}
	return false
}

// text replaces the secrets in any form inside s.
func (rd *redactor) text(s string) string {
	if rd.re != nil {
		s = rd.re.ReplaceAllString(s, Redacted)
	}
	// Addresses nobody listed (on a page, in a title) go too.
	return emailRe.ReplaceAllStringFunc(s, func(m string) string {
		if isEmail(m) && !isProbe(m) {
			return Redacted
		}
		return m
	})
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

// url redacts a URL or a page path: the query pair by pair, the rest as text.
func (rd *redactor) url(s string) string {
	// Known values first, whole, before the query is cut into pairs.
	s = rd.text(s)
	base, frag, hasFrag := strings.Cut(s, "#")
	path, q, hasQ := strings.Cut(base, "?")
	out := rd.text(path)
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
func (rd *redactor) body(reqURL, body, ctype string) string {
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

// apply redacts the result in place, and the requests it will write.
func (rd *redactor) apply(res *Result, reqs []Request) {
	walkStrings(reflect.ValueOf(res), func(s string) string {
		s = rd.text(s)
		if looksLikeURL(s) {
			return rd.url(s)
		}
		// A sentence can quote a page address; redact the addresses in it
		// pair by pair too.
		words := strings.Split(s, " ")
		for i, w := range words {
			if strings.Contains(w, "?") && (strings.HasPrefix(w, "/") || strings.Contains(w, "://")) {
				words[i] = rd.url(w)
			}
		}
		return rd.text(rd.opaque(strings.Join(words, " ")))
	})
	if res.Analysis != nil {
		for _, f := range res.Findings {
			f.Evidence.Body = rd.body(f.Evidence.URL, f.Evidence.Body, "")
		}
	}
	for i := range reqs {
		r := &reqs[i]
		r.Body = rd.body(r.URL, r.Body, r.ContentType)
		r.URL = rd.url(r.URL)
		for k, v := range r.Headers {
			if secretHeaders[strings.ToLower(k)] {
				r.Headers[k] = Redacted
			} else if looksLikeURL(v) {
				r.Headers[k] = rd.url(v)
			} else {
				r.Headers[k] = rd.text(v)
			}
		}
	}
	res.Redacted = true
}

// walkStrings calls fn on every settable string reachable from v and
// stores what it returns. Map keys are left alone (passes and severities).
func walkStrings(v reflect.Value, fn func(string) string) {
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface:
		if !v.IsNil() {
			walkStrings(v.Elem(), fn)
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if t.Field(i).IsExported() {
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
	return rd
}

// VerifyRedacted reads the files an audit wrote and fails if any personal
// value the redactor knew about, or any email address other than the
// probe, is still in them in any form.
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
			if rd.re != nil {
				if m := rd.re.FindString(v); m != "" {
					return fmt.Errorf("redaction check: %s still holds a personal value (%d characters)", name, len(m))
				}
			}
			for _, m := range emailRe.FindAllString(v, -1) {
				if isEmail(m) && !isProbe(m) {
					return fmt.Errorf("redaction check: %s still holds an email address", name)
				}
			}
		}
		if name == "requests.har" {
			if err := rd.verifyHAR(b); err != nil {
				return err
			}
		}
	}
	return nil
}

// verifyHAR decodes every recorded request the way the audit does (base64,
// JSON, nested parameters) and fails on a personal value in any of them.
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
		for _, p := range DecodeRequest(e.Request.URL, body, ctype) {
			if rd.leaks(p.Value) {
				return fmt.Errorf("redaction check: requests.har entry %d still carries a personal value", i+1)
			}
		}
	}
	return nil
}
