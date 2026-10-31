package pxta

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func checkFixture() *Result {
	return &Result{Tool: "pxta", Site: "https://shop.test/", Banner: Banner{Found: true, Platform: "onetrust"},
		Analysis: &Analysis{
			Counts: map[string]int{SevHigh: 1, SevMedium: 1, SevLow: 1, SevInfo: 2},
			Findings: []*Finding{
				{Code: CodePersonalData, Severity: SevHigh, Pass: PassNone, Page: "/checkout", Tracker: "meta-pixel", Sentence: "personal data", Count: 2},
				{Code: CodeTrackerBeforeConsent, Severity: SevMedium, Pass: PassNone, Page: "/", Tracker: "google-analytics-4", Sentence: "before consent", Count: 1},
				{Code: CodePersonalData, Severity: SevLow, Pass: PassAccept, Page: "/blog/2026/post", Tracker: "meta-pixel", Sentence: "after accept", Count: 1},
				{Code: CodeTrackerPresent, Severity: SevInfo, Pass: PassAccept, Tracker: "meta-pixel", Sentence: "present", Count: 3},
				{Code: CodeBannerNotHandled, Severity: SevInfo, Pass: PassReject, Sentence: "could not reject"},
			},
			Trackers: []TrackerUse{
				{ID: "meta-pixel", Name: "Meta Pixel", Fired: map[string][]string{PassNone: {"/checkout", "/"}}},
				{ID: "google-analytics-4", Name: "Google Analytics 4", Fired: map[string][]string{PassNone: {"/"}}},
			},
		}}
}

func codes(ps []Problem) string {
	var l []string
	for _, p := range ps {
		l = append(l, p.Code+"/"+p.Pass)
	}
	return strings.Join(l, ",")
}

func TestCheckDefaults(t *testing.T) {
	c := Check(checkFixture(), nil)
	if c.Pass {
		t.Fatal("default rules passed a site with a high finding")
	}
	// medium and above, plus banner-not-handled; never the info presence rows
	// or the low after-accept finding.
	if got, want := codes(c.Failed), "personal-data/none,tracker-before-consent/none,banner-not-handled/reject"; got != want {
		t.Fatalf("failed %s, want %s", got, want)
	}
}

func TestCheckFailOnAndCodes(t *testing.T) {
	r, err := ParseRules([]byte(`{"fail_on":"high","fail_codes":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	c := Check(checkFixture(), r)
	if got := codes(c.Failed); got != "personal-data/none" {
		t.Fatalf("fail_on high, no codes: %s", got)
	}
	r, _ = ParseRules([]byte(`{"fail_on":"never","fail_codes":["search-term"]}`))
	if c := Check(checkFixture(), r); !c.Pass {
		t.Fatalf("fail_on never passed nothing: %s", codes(c.Failed))
	}
	r, _ = ParseRules([]byte(`{"fail_on":"low"}`))
	if c := Check(checkFixture(), r); len(c.Failed) != 4 {
		t.Fatalf("fail_on low: %s", codes(c.Failed))
	}
}

func TestCheckAllow(t *testing.T) {
	r, err := ParseRules([]byte(`{"allow":[
	  {"code":"tracker-before-consent","tracker":"google-analytics-4","page":"/","reason":"cookieless ping, legal OK"},
	  {"code":"banner-not-handled","reason":"reject button is a link, ticket 42","until":"2026-11-30"},
	  {"code":"personal-data","page":"/checkout","reason":"old","until":"2026-10-01"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	r.now = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	c := Check(checkFixture(), r)
	if got := codes(c.Failed); got != "personal-data/none" {
		t.Fatalf("failed %s", got)
	}
	if len(c.Allowed) != 2 || c.Allowed[0].AllowedBy != "cookieless ping, legal OK" {
		t.Fatalf("allowed %+v", c.Allowed)
	}
	if len(c.Expired) != 1 || c.Expired[0].Until != "2026-10-01" {
		t.Fatalf("expired %+v", c.Expired)
	}
	// The until day itself still counts; the day after doesn't.
	r.now = time.Date(2026, 11, 30, 23, 0, 0, 0, time.UTC)
	if c := Check(checkFixture(), r); len(c.Allowed) != 2 {
		t.Fatalf("until day: allowed %d", len(c.Allowed))
	}
	r.now = time.Date(2026, 12, 1, 0, 30, 0, 0, time.UTC)
	if c := Check(checkFixture(), r); len(c.Allowed) != 1 {
		t.Fatalf("day after until: allowed %d", len(c.Allowed))
	}
}

func TestCheckPagePatterns(t *testing.T) {
	for _, tc := range []struct {
		pattern, page string
		want          bool
	}{
		{"/blog/*", "/blog/2026/post", true},
		{"/blog/*", "/blog", false},
		{"/checkout", "/checkout?order=1", true},
		{"/check*", "/checkout", true},
		{"/checkout", "/checkout/confirm", false},
		{"/", "/", true},
		{"/x", "", false},
	} {
		a := Allowance{Page: tc.pattern, Reason: "r"}
		if got := a.matches(Problem{Page: tc.page}); got != tc.want {
			t.Errorf("%s vs %s: %v", tc.pattern, tc.page, got)
		}
	}
}

func TestCheckTrackers(t *testing.T) {
	r, _ := ParseRules([]byte(`{"fail_on":"never","fail_codes":[],"trackers":{"allow":["google-analytics-4"]}}`))
	c := Check(checkFixture(), r)
	if got := codes(c.Failed); got != "tracker-not-allowed/" || c.Failed[0].Tracker != "meta-pixel" || c.Failed[0].Page != "/" {
		t.Fatalf("allow list: %s %+v", got, c.Failed)
	}
	r, _ = ParseRules([]byte(`{"fail_on":"never","fail_codes":[],"trackers":{"block":["google-analytics-4"]}}`))
	c = Check(checkFixture(), r)
	if got := codes(c.Failed); got != "tracker-blocked/" {
		t.Fatalf("block list: %s", got)
	}
	res := checkFixture()
	res.Banner = Banner{}
	r, _ = ParseRules([]byte(`{"fail_on":"never","fail_codes":[],"require_banner":true}`))
	if c := Check(res, r); codes(c.Failed) != "no-banner/" {
		t.Fatalf("require_banner: %s", codes(c.Failed))
	}
	res.Analysis.Trackers = nil
	if c := Check(res, r); !c.Pass {
		t.Fatal("require_banner failed a site without trackers")
	}
}

func TestRulesRejected(t *testing.T) {
	for _, bad := range []string{
		`{"fail_on":"critical"}`,
		`{"fail_codes":["tracker-before-consnet"]}`,
		`{"allow":[{"code":"personal-data"}]}`,
		`{"allow":[{"reason":"everything"}]}`,
		`{"allow":[{"code":"personal-data","reason":"r","until":"31/12/2026"}]}`,
		`{"allow":[{"page":"checkout","reason":"r"}]}`,
		`{"allow":[{"pass":"later","reason":"r"}]}`,
		`{"fail_onn":"high"}`,
		`{"trackers":{"allow":[""]}}`,
		`{} {}`,
		`not json`,
	} {
		if _, err := ParseRules([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestCheckOutputs(t *testing.T) {
	c := Check(checkFixture(), nil)
	var b bytes.Buffer
	c.WriteText(&b, false)
	if !strings.Contains(b.String(), "pxta check: fail, 3 problems") || !strings.Contains(b.String(), "personal data") {
		t.Errorf("text:\n%s", b.String())
	}
	b.Reset()
	res := checkFixture()
	res.Findings[0].Tracker = "a,b:c"
	res.Findings[0].Name = "Pixel: 50%"
	Check(res, nil).WriteGitHub(&b)
	line := strings.SplitN(b.String(), "\n", 2)[0]
	if line != "::error title=pxta personal-data (a%2Cb%3Ac)::Pixel: 50%25 sent personal data on /checkout (before an answer), 2 times." {
		t.Errorf("annotation %q", line)
	}
	md := Check(res, nil).Markdown()
	if !strings.Contains(md, "## PXTA check failed") || !strings.Contains(md, "Pixel: 50% sent personal data on /checkout") {
		t.Errorf("markdown:\n%s", md)
	}
	pass := Check(&Result{Tool: "pxta", Site: "s", Analysis: &Analysis{}}, nil)
	if !pass.Pass || !strings.Contains(pass.Markdown(), "passed") {
		t.Error("empty result did not pass")
	}
}

func TestPublicOutputs(t *testing.T) {
	secret := "jane@example.com"
	sentence := "On /checkout/confirm (order=1&email=" + secret + "), the Meta Pixel sent " + sha(secret) +
		" and jane%40example.com and Jane Roe before the consent banner was answered."
	res := checkFixture()
	res.Findings[0].Sentence = sentence
	res.Findings[0].Page = "/checkout/jane%40example.com/" + sha(secret) + "?email=" + secret
	res.Findings[1].Tracker = "unclassified:jane.example.net"
	c := Check(res, nil)
	var gh, txt bytes.Buffer
	c.WriteGitHub(&gh)
	c.WriteText(&txt, true)
	for name, out := range map[string]string{"annotations": gh.String(), "summary": c.Markdown(), "log": txt.String()} {
		for _, bad := range []string{"jane", "Jane", sha(secret)[:16], "email="} {
			if strings.Contains(out, bad) {
				t.Errorf("%s holds %q:\n%s", name, bad, out)
			}
		}
	}
	if !strings.Contains(gh.String(), "on /checkout/REDACTED/REDACTED") || !strings.Contains(gh.String(), "An unrecognised tracker") {
		t.Errorf("annotations:\n%s", gh.String())
	}
	if got := PublicPath("/blog/2026/post?x=1#y"); got != "/blog/2026/post" {
		t.Errorf("PublicPath %q", got)
	}
	// Without public, the local text log keeps the full sentence.
	txt.Reset()
	c.WriteText(&txt, false)
	if !strings.Contains(txt.String(), "Jane Roe") {
		t.Error("local text lost the sentence")
	}
}

func TestRulesTrackersAndPatterns(t *testing.T) {
	cat, err := LoadCatalog("")
	if err != nil {
		t.Fatal(err)
	}
	for doc, ok := range map[string]bool{
		`{"trackers":{"allow":["meta-pixel","unclassified:cdn.example"]}}`: true,
		`{"trackers":{"allow":["meta_pixel"]}}`:                            false,
		`{"trackers":{"block":["tiktok"]}}`:                                false,
		`{"allow":[{"tracker":"metapixel","reason":"r"}]}`:                 false,
	} {
		r, err := ParseRules([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		if err := r.CheckTrackers(cat); (err == nil) != ok {
			t.Errorf("%s: %v", doc, err)
		}
	}
	if _, err := ParseRules([]byte(`{"allow":[{"page":"/[blog","reason":"r"}]}`)); err == nil {
		t.Error("bad glob accepted")
	}
}
