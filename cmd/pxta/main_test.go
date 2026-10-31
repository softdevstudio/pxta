package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/softdevstudio/pxta"
)

func TestCLI(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"version"}, &out, &errb); code != 0 || out.String() != "pxta "+pxta.Version+"\n" {
		t.Errorf("version: %d %q", code, out.String())
	}
	out.Reset()
	if code := run([]string{"catalog"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "meta-pixel") || !strings.Contains(out.String(), "10 trackers") {
		t.Errorf("catalog: %d %q", code, out.String())
	}
	errb.Reset()
	if code := run(nil, &out, &errb); code != 2 || !strings.Contains(errb.String(), "Usage") {
		t.Errorf("no args: %d %q", code, errb.String())
	}
	errb.Reset()
	if code := run([]string{"bogus"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "unknown command") {
		t.Errorf("unknown: %d %q", code, errb.String())
	}
	errb.Reset()
	if code := run([]string{"audit"}, &out, &errb); code != 2 {
		t.Errorf("audit without a URL: %d", code)
	}
	errb.Reset()
	if code := run([]string{"audit", "https://example.com", "--passes", "maybe"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "unknown pass") {
		t.Errorf("bad pass: %d %q", code, errb.String())
	}
	errb.Reset()
	if code := run([]string{"audit", "ftp://example.com"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "http(s)") {
		t.Errorf("bad scheme: %d %q", code, errb.String())
	}
}

// writeFindings saves a small audit result as an audit would.
func writeFindings(t *testing.T, findings []*pxta.Finding) string {
	t.Helper()
	res := &pxta.Result{Tool: "pxta", Version: pxta.Version, Site: "https://shop.test/", Analysis: &pxta.Analysis{
		Findings: findings, Counts: map[string]int{}}}
	for _, f := range findings {
		res.Counts[f.Severity]++
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "findings.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckCLI(t *testing.T) {
	bad := writeFindings(t, []*pxta.Finding{
		{Code: pxta.CodeTrackerBeforeConsent, Severity: pxta.SevMedium, Pass: "none", Page: "/", Tracker: "meta-pixel",
			Sentence: "On /, the Meta Pixel sent PageView before the consent banner was answered."},
	})
	good := writeFindings(t, []*pxta.Finding{
		{Code: pxta.CodeTrackerPresent, Severity: pxta.SevInfo, Pass: "accept", Tracker: "meta-pixel", Sentence: "present"},
	})
	var out, errb bytes.Buffer
	if code := run([]string{"check", "--findings", good}, &out, &errb); code != 0 || !strings.Contains(out.String(), "pxta check: pass") {
		t.Errorf("good: %d %q %q", code, out.String(), errb.String())
	}
	out.Reset()
	summary := filepath.Join(t.TempDir(), "summary.md")
	if code := run([]string{"check", "--findings", bad, "--format", "github", "--summary", summary}, &out, &errb); code != 1 {
		t.Errorf("bad: %d %q", code, out.String())
	}
	if !strings.Contains(out.String(), "::error title=pxta tracker-before-consent (meta-pixel)::") {
		t.Errorf("annotation missing: %q", out.String())
	}
	md, _ := os.ReadFile(summary)
	if !strings.Contains(string(md), "## PXTA check failed") {
		t.Errorf("summary: %q", md)
	}
	// An allow entry with a reason lets it through.
	rules := filepath.Join(t.TempDir(), "rules.json")
	os.WriteFile(rules, []byte(`{"allow":[{"code":"tracker-before-consent","tracker":"meta-pixel","reason":"legal approved, ticket 7"}]}`), 0o644)
	out.Reset()
	if code := run([]string{"check", "--findings", bad, "--rules", rules}, &out, &errb); code != 0 || !strings.Contains(out.String(), "legal approved") {
		t.Errorf("allowed: %d %q", code, out.String())
	}
	// Usage and rules errors are 2, never 0 or 1.
	os.WriteFile(rules, []byte(`{"fail_on":"sometimes"}`), 0o644)
	for _, args := range [][]string{
		{"check"},
		{"check", "--findings", bad, "--rules", rules},
		{"check", "--findings", bad, "--rules", filepath.Join(t.TempDir(), "missing.json")},
		{"check", "--findings", bad, "https://shop.test/"},
		{"check", "--findings", bad, "--format", "xml"},
		{"check", "--findings", filepath.Join(t.TempDir(), "nope.json")},
		{"check", "ftp://shop.test/"},
		{"check", "--findings", bad, "--redact"},
	} {
		errb.Reset()
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("%v: exit %d (%s)", args, code, errb.String())
		}
	}
}

func writeAudit(t *testing.T, findings []*pxta.Finding) string {
	t.Helper()
	res := &pxta.Result{Tool: "pxta", Version: pxta.Version, Site: "https://shop.test/", Passes: []string{"none", "reject", "accept"},
		Analysis: &pxta.Analysis{Findings: findings, Counts: map[string]int{}}}
	for _, pass := range res.Passes {
		res.Pages = append(res.Pages, pxta.Visit{Pass: pass, URL: "https://shop.test/", FinalURL: "https://shop.test/"})
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "findings.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDiffCLI(t *testing.T) {
	low := &pxta.Finding{Code: pxta.CodeSearchTerm, Severity: pxta.SevLow, Pass: "accept", Page: "/", Tracker: "meta-pixel",
		Sentence: "On /, the Meta Pixel sent the search term “cake” after the visitor accepted tracking.",
		Evidence: pxta.Evidence{Highlight: []pxta.Leak{{Rule: "search_term", Key: "q", Value: "cake"}}}}
	med := &pxta.Finding{Code: pxta.CodeTrackerBeforeConsent, Severity: pxta.SevMedium, Pass: "none", Page: "/", Tracker: "x-pixel", Name: "X Pixel",
		Sentence: "On /, the X Pixel sent a request before the consent banner was answered."}
	old := writeAudit(t, nil)
	same := writeAudit(t, nil)
	onlyLow := writeAudit(t, []*pxta.Finding{low})
	both := writeAudit(t, []*pxta.Finding{low, med})
	var out, errb bytes.Buffer
	if code := run([]string{"diff", old, same}, &out, &errb); code != 0 || !strings.Contains(out.String(), "pxta diff: no change") {
		t.Errorf("same: %d %q %q", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"diff", old, onlyLow}, &out, &errb); code != 1 || !strings.Contains(out.String(), "New findings (1)") {
		t.Errorf("any change: %d %q", code, out.String())
	}
	out.Reset()
	if code := run([]string{"diff", "--fail-on", "medium", old, onlyLow}, &out, &errb); code != 0 {
		t.Errorf("fail-on medium, low added: %d", code)
	}
	out.Reset()
	summary := filepath.Join(t.TempDir(), "summary.md")
	jsonOut := filepath.Join(t.TempDir(), "diff.json")
	if code := run([]string{"diff", onlyLow, both, "--fail-on", "medium", "--format", "github", "--summary", summary, "--out", jsonOut}, &out, &errb); code != 1 {
		t.Errorf("fail-on medium, medium added: %d %q", code, out.String())
	}
	if !strings.Contains(out.String(), "::error title=pxta diff new tracker-before-consent (x-pixel)::X Pixel sent data before the consent banner was answered on / (before an answer).") {
		t.Errorf("annotation: %q", out.String())
	}
	md, _ := os.ReadFile(summary)
	if !strings.Contains(string(md), "## PXTA diff: 1 new, 0 gone") {
		t.Errorf("summary: %q", md)
	}
	var d pxta.DiffResult
	if b, err := os.ReadFile(jsonOut); err != nil || json.Unmarshal(b, &d) != nil || len(d.Added) != 1 || !d.Fail {
		t.Errorf("diff.json: %v %+v", err, d)
	}
	out.Reset()
	if code := run([]string{"diff", "--format", "json", both, onlyLow}, &out, &errb); code != 1 || !strings.Contains(out.String(), `"gone_findings": [`) {
		t.Errorf("json: %d %q", code, out.String())
	}
	for _, bad := range [][]string{{"diff", old}, {"diff", old, same, "--fail-on", "critical"}, {"diff", "--format", "xml", old, same}} {
		if code := run(bad, &out, &errb); code != 2 {
			t.Errorf("%v: %d", bad, code)
		}
	}
	if code := run([]string{"diff", old, filepath.Join(t.TempDir(), "missing.json")}, &out, &errb); code != 3 {
		t.Errorf("missing file: %d", code)
	}
}
