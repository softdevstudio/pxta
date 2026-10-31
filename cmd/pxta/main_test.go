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
	if !strings.Contains(out.String(), "::error title=pxta tracker-before-consent (meta-pixel)::On /, the Meta Pixel") {
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
