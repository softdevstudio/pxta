package pxta

import (
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
