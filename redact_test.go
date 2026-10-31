package pxta

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func md(s string) string  { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) }

// redactFixture is an audit result whose requests carry one person's data in
// every form PXTA decodes, plus PXTA's own probe values.
func redactFixture(t *testing.T) (*Result, *Emails, *Catalog) {
	t.Helper()
	cat, err := LoadCatalog("")
	if err != nil {
		t.Fatal(err)
	}
	const jane = "jane.doe@example.org"
	b64 := base64.StdEncoding.EncodeToString([]byte(`{"em":"` + jane + `","x":1}`))
	page := "https://shop.test/checkout/confirm?order=10442&email=" + url.QueryEscape(jane)
	reqs := []Request{
		{Pass: PassNone, Page: 0, Time: time.Unix(1, 0), Method: "GET", Type: "Image", Target: "page", Phase: "load",
			URL: "https://www.facebook.com/tr/?id=123456789&ev=PageView&dl=" + url.QueryEscape(page) + "&ud[em]=" + sha(jane) +
				"&fbp=fb.1.1700000000000.1234567890",
			Headers: map[string]string{"Cookie": "_fbp=fb.1.1700000000000.1234567890; sid=s3cr3tsession42", "Referer": page}},
		{Pass: PassNone, Page: 0, Time: time.Unix(2, 0), Method: "POST", Type: "Fetch", Target: "page", Phase: "load",
			URL:         "https://analytics.tiktok.com/api/v2/pixel?blob=" + url.QueryEscape(b64),
			ContentType: "application/json",
			Body:        `{"context":{"page":{"url":"` + page + `"}},"properties":{"email":"` + jane + `","phone":"+44 20 7946 0958"}}`},
		{Pass: PassReject, Page: 0, Time: time.Unix(3, 0), Method: "POST", Type: "Beacon", Target: "page", Phase: "unload",
			URL:         "https://bat.bing.com/action/0?ti=5",
			ContentType: "application/x-www-form-urlencoded",
			Body:        "em=" + url.QueryEscape(url.QueryEscape(jane)) + "&probe=" + url.QueryEscape(ProbeEmail) + "&h=" + strings.ToUpper(md(jane))},
		{Pass: PassNone, Page: 1, Time: time.Unix(4, 0), Method: "GET", Type: "Image", Target: "page", Phase: "load",
			URL: "https://www.facebook.com/tr/?id=123456789&ev=Lead&ud[em]=" + sha(ProbeEmail)},
	}
	emails := NewEmails()
	emails.Add(jane)
	emails.Add(ProbeEmail)
	visits := []Visit{
		{Pass: PassNone, Page: 0, URL: page, FinalURL: page, Title: "Order for " + jane},
		{Pass: PassReject, Page: 0, URL: page, FinalURL: page},
		{Pass: PassNone, Page: 1, URL: "https://shop.test/newsletter", FinalURL: "https://shop.test/newsletter"},
	}
	res := &Result{Tool: "pxta", Version: Version, Site: "https://shop.test/", Started: time.Unix(0, 0).UTC(),
		Passes: []string{PassNone, PassReject}, Pages: visits, Emails: emails.List(), requests: reqs}
	res.Analysis = Analyze(cat, visits, reqs, emails, "pxta audit")
	return res, emails, cat
}

func TestRedact(t *testing.T) {
	res, emails, cat := redactFixture(t)
	before := map[string]int{}
	for k, v := range res.Counts {
		before[k] = v
	}
	nFindings := len(res.Findings)
	if before[SevHigh] == 0 {
		t.Fatal("fixture has no high findings")
	}
	rd := Redact(res, emails, cat)
	res.redactor = rd
	dir := t.TempDir()
	if err := WriteOutputs(res, dir); err != nil {
		t.Fatal(err)
	}
	if err := res.VerifyRedacted(dir); err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != nFindings || res.Counts[SevHigh] != before[SevHigh] {
		t.Errorf("redaction changed the findings: %d -> %d, high %d -> %d", nFindings, len(res.Findings), before[SevHigh], res.Counts[SevHigh])
	}
	jane := "jane.doe@example.org"
	b64 := base64.StdEncoding.EncodeToString([]byte(`{"em":"` + jane + `","x":1}`))
	for _, name := range []string{"findings.json", "report.html", "requests.har"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		low := strings.ToLower(string(b))
		for _, bad := range []string{"jane.doe", "jane.doe%40", "jane.doe%2540", sha(jane), md(jane), "s3cr3tsession42",
			"1234567890", "7946", strings.ToLower(url.QueryEscape(b64)), strings.ToLower(b64[:20])} {
			if strings.Contains(low, strings.ToLower(bad)) {
				t.Errorf("%s still holds %q", name, bad)
			}
		}
		if !strings.Contains(string(b), Redacted) {
			t.Errorf("%s has no REDACTED marker", name)
		}
	}
	har, _ := os.ReadFile(filepath.Join(dir, "requests.har"))
	// The probe address and its hash are evidence and stay.
	if !strings.Contains(string(har), url.QueryEscape(ProbeEmail)) || !strings.Contains(string(har), sha(ProbeEmail)) {
		t.Error("the probe address or its hash was redacted")
	}
	// The parts that aren't personal stay readable.
	for _, keep := range []string{"ev=PageView", "id=123456789", "bat.bing.com", "/checkout/confirm"} {
		if !strings.Contains(string(har), keep) {
			t.Errorf("requests.har lost %q", keep)
		}
	}
	html, _ := os.ReadFile(filepath.Join(dir, "report.html"))
	if !strings.Contains(string(html), "replaced by REDACTED") {
		t.Error("report does not say it is redacted")
	}
}

// The scan after writing catches a value the redactor missed, in any form.
func TestVerifyRedactedCatches(t *testing.T) {
	res, emails, cat := redactFixture(t)
	rd := Redact(res, emails, cat)
	for _, leak := range []string{
		"jane.doe@example.org",
		"jane.doe%40example.org",
		"JANE.DOE%2540EXAMPLE.ORG",
		strings.ToUpper(sha("jane.doe@example.org")),
		"stranger@other.test",
	} {
		dir := t.TempDir()
		res.redactor = rd
		if err := WriteOutputs(res, dir); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "findings.json")
		b, _ := os.ReadFile(p)
		os.WriteFile(p, append(b, []byte(leak)...), 0o644)
		if err := res.VerifyRedacted(dir); err == nil {
			t.Errorf("verify missed %q", leak)
		}
	}
	// A base64 blob that hides an address is caught in the HAR by decoding.
	dir := t.TempDir()
	WriteOutputs(res, dir)
	p := filepath.Join(dir, "requests.har")
	b, _ := os.ReadFile(p)
	blob := url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(`{"e":"jane.doe@example.org"}`)))
	b = []byte(strings.Replace(string(b), "ti=5", "ti=5&z="+blob, 1))
	os.WriteFile(p, b, 0o644)
	if err := res.VerifyRedacted(dir); err == nil {
		t.Error("verify missed a base64-carried address in the HAR")
	}
}

func TestRedactSentencePaths(t *testing.T) {
	rd := &redactor{secrets: map[string]bool{}}
	rd.addEmail("a.person@mail.test")
	rd.compile()
	got := rd.text("On /confirm?email=a.person%40mail.test&x=1, the Meta Pixel sent a SHA-256 hash of the email address a.person@mail.test.")
	if strings.Contains(got, "a.person") || strings.Contains(got, sha("a.person@mail.test")) || !strings.Contains(got, "x=1") {
		t.Errorf("sentence: %s", got)
	}
	if got := rd.url("/p?q=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("a.person@mail.test"))) + "&k=v"); got != "/p?q=REDACTED&k=v" {
		t.Errorf("url: %s", got)
	}
}

// redactOne audits nothing: it builds a result around one request to a
// third-party host, analyses it the way a redacted audit does, writes the
// report and runs the after-write scan.
func redactOne(t *testing.T, page, reqURL string) (*Result, string, error) {
	t.Helper()
	cat, err := LoadCatalog("")
	if err != nil {
		t.Fatal(err)
	}
	reqs := []Request{{Pass: PassNone, Page: 0, Time: time.Unix(1, 0), Method: "GET", Type: "Image", Target: "page", Phase: "load", URL: reqURL}}
	visits := []Visit{{Pass: PassNone, Page: 0, URL: page, FinalURL: page, Started: time.Unix(1, 0)}}
	emails := NewEmails()
	res := &Result{Tool: "pxta", Version: Version, Site: "https://shop.test/", Started: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC),
		Passes: []string{PassNone}, Pages: visits, requests: reqs, Settings: Settings{MaxPages: 100, RespectRobot: true}}
	rd := newRedactor(res, reqs, emails, cat)
	res.Analysis = analyze(cat, visits, reqs, emails, "pxta audit", rd.url)
	rd.apply(res, res.requests)
	res.redactor = rd
	dir := t.TempDir()
	if err := WriteOutputs(res, dir); err != nil {
		t.Fatal(err)
	}
	return res, dir, res.VerifyRedacted(dir)
}

// Short names and IDs match only as whole words: they must not cut into
// field names, codes, tracker IDs, timestamps or the word REDACTED, and the
// scan must not fail the run over them.
func TestRedactShortValues(t *testing.T) {
	for _, name := range []string{"Tim", "Rob", "Eve", "Ann", "Max", "Ed", "Al"} {
		res, dir, err := redactOne(t, "https://shop.test/",
			"https://b.other.test/collect?fn="+name+"&email=someone%40example.org&uid=100200")
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		b, _ := os.ReadFile(filepath.Join(dir, "findings.json"))
		s := string(b)
		for _, keep := range []string{`"code": "personal-data"`, `"tracker": "unclassified:b.other.test"`, "2026-10-31", `"respect_robots": true`, `"max_pages": 100`} {
			if !strings.Contains(s, keep) {
				t.Errorf("%s: findings.json lost %q", name, keep)
			}
		}
		if strings.Contains(s, "RREDACTED") || strings.Contains(s, "REDACTEDACT") {
			t.Errorf("%s: REDACTED was redacted again", name)
		}
		if len(name) >= minName && strings.Contains(s, "fn="+name) {
			t.Errorf("%s: the name survived", name)
		}
		if strings.Contains(s, "someone") {
			t.Errorf("%s: the address survived", name)
		}
		if len(res.Findings) == 0 {
			t.Errorf("%s: no findings", name)
		}
	}
}

// A long page address is redacted before it's shortened for sentences, so
// no cut-off piece of an address or hash is left.
func TestRedactLongPagePaths(t *testing.T) {
	long := "jonathan.verylongname@example.org"
	page := "https://shop.test/account/view?ref=" + strings.Repeat("x", 30) + "&email=" + url.QueryEscape(long)
	_, dir, err := redactOne(t, page, "https://b.other.test/collect?dl="+url.QueryEscape(page)+"&email="+url.QueryEscape(long))
	if err != nil {
		t.Fatal(err)
	}
	page2 := "https://shop.test/a/b?ref=" + strings.Repeat("y", 40) + "&eh=" + sha(long)
	_, dir2, err := redactOne(t, page2, "https://b.other.test/collect?dl="+url.QueryEscape(page2)+"&email="+url.QueryEscape(long))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{dir, dir2} {
		for _, name := range []string{"findings.json", "report.html"} {
			b, _ := os.ReadFile(filepath.Join(d, name))
			if strings.Contains(string(b), "jonathan") || strings.Contains(string(b), sha(long)[:12]) {
				t.Errorf("%s keeps part of the address or its hash", name)
			}
		}
	}
}

// base64 in a URL path segment is redacted and, if left, caught.
func TestRedactPathSegments(t *testing.T) {
	blob := base64.RawURLEncoding.EncodeToString([]byte(`{"e":"jane@example.org","t":1}`))
	_, dir, err := redactOne(t, "https://shop.test/",
		"https://b.other.test/p/"+blob+"/x?email=jane%40example.org")
	if err != nil {
		t.Fatal(err)
	}
	har, _ := os.ReadFile(filepath.Join(dir, "requests.har"))
	if strings.Contains(string(har), blob) {
		t.Error("the base64 path segment survived")
	}
	if !strings.Contains(string(har), "b.other.test/p/REDACTED/x") {
		t.Errorf("path not kept around the segment: %s", har)
	}
}

// A redacted audit that fails leaves no raw data in --out, working files
// included; an unredacted one leaves them for --resume.
func TestRedactFailureCleansUp(t *testing.T) {
	for _, redact := range []bool{true, false} {
		dir := t.TempDir()
		names := []string{"findings.json", "report.html", "requests.har", "state.json", "requests.jsonl"}
		for _, n := range names {
			os.WriteFile(filepath.Join(dir, n), []byte("jane@example.org"), 0o644)
		}
		_, err := Audit(context.Background(), Options{StartURL: "ftp://bad", OutDir: dir, Redact: redact})
		if err == nil {
			t.Fatal("bad address accepted")
		}
		for _, n := range names {
			_, statErr := os.Stat(filepath.Join(dir, n))
			if redact && statErr == nil {
				t.Errorf("redacted failure left %s", n)
			}
			if !redact && statErr != nil {
				t.Errorf("unredacted failure removed %s", n)
			}
		}
	}
}
