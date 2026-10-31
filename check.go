package pxta

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Rules decide which audit results fail a check. The file is JSON; every
// field is optional and unknown fields are an error.
type Rules struct {
	// FailOn is the lowest severity that fails: high, medium, low, info or
	// never. Default medium.
	FailOn string `json:"fail_on,omitempty"`
	// FailCodes fail whatever their severity. Default banner-not-handled,
	// so a check that couldn't run its reject pass never passes quietly.
	FailCodes []string `json:"fail_codes,omitempty"`
	// Trackers limits which trackers may be on the site at all.
	Trackers TrackerRules `json:"trackers,omitempty"`
	// RequireBanner fails a site that has trackers but no consent banner.
	RequireBanner bool `json:"require_banner,omitempty"`
	// Allow lists accepted exceptions.
	Allow []Allowance `json:"allow,omitempty"`

	failCodesSet bool
	now          time.Time
}

// TrackerRules: with Allow set, any other tracker fails; Block always fails.
type TrackerRules struct {
	Allow []string `json:"allow,omitempty"`
	Block []string `json:"block,omitempty"`
}

// Allowance excuses the problems it matches. Code, Tracker, Page and Pass
// narrow it (empty means any); Page is a path pattern with * wildcards.
// Reason is required. Until is the last day it applies (YYYY-MM-DD).
type Allowance struct {
	Code    string `json:"code,omitempty"`
	Tracker string `json:"tracker,omitempty"`
	Page    string `json:"page,omitempty"`
	Pass    string `json:"pass,omitempty"`
	Reason  string `json:"reason"`
	Until   string `json:"until,omitempty"`

	until time.Time
}

// Problem kinds a check reports besides finding codes.
const (
	ProblemTrackerNotAllowed = "tracker-not-allowed"
	ProblemTrackerBlocked    = "tracker-blocked"
	ProblemNoBanner          = "no-banner"
)

var knownCodes = map[string]bool{
	CodeTrackerBeforeConsent: true, CodeTrackerAfterReject: true, CodePersonalData: true, CodeSensitivePage: true,
	CodeSearchTerm: true, CodeConsentModeGranted: true, CodeConsentModeMismatch: true, CodeBannerNotHandled: true,
	CodeTrackerPresent: true, ProblemTrackerNotAllowed: true, ProblemTrackerBlocked: true, ProblemNoBanner: true,
}

// DefaultRules is what a check uses without a rules file.
func DefaultRules() *Rules {
	r := &Rules{}
	if err := r.prepare(); err != nil {
		panic(err)
	}
	return r
}

// LoadRules reads and validates a rules file.
func LoadRules(file string) (*Rules, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	r, err := ParseRules(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return r, nil
}

// ParseRules validates a rules document.
func ParseRules(b []byte) (*Rules, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r Rules
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("rules: more than one JSON value")
	}
	// fail_codes given as [] means "none", so tell it apart from missing.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err == nil {
		_, r.failCodesSet = raw["fail_codes"]
	}
	if err := r.prepare(); err != nil {
		return nil, err
	}
	return &r, nil
}

func (r *Rules) prepare() error {
	if r.FailOn == "" {
		r.FailOn = SevMedium
	}
	if r.FailOn != "never" && sevRank[r.FailOn] == 0 {
		return fmt.Errorf("rules: fail_on %q: use high, medium, low, info or never", r.FailOn)
	}
	if !r.failCodesSet && r.FailCodes == nil {
		r.FailCodes = []string{CodeBannerNotHandled}
	}
	for _, c := range r.FailCodes {
		if !knownCodes[c] {
			return fmt.Errorf("rules: fail_codes: unknown code %q", c)
		}
	}
	for _, id := range append(append([]string{}, r.Trackers.Allow...), r.Trackers.Block...) {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("rules: trackers: empty tracker id")
		}
	}
	for i := range r.Allow {
		a := &r.Allow[i]
		at := fmt.Sprintf("rules: allow[%d]", i)
		if strings.TrimSpace(a.Reason) == "" {
			return fmt.Errorf("%s: a reason is required", at)
		}
		if a.Code != "" && !knownCodes[a.Code] {
			return fmt.Errorf("%s: unknown code %q", at, a.Code)
		}
		switch a.Pass {
		case "", PassNone, PassReject, PassAccept, PassNoBanner:
		default:
			return fmt.Errorf("%s: unknown pass %q", at, a.Pass)
		}
		if a.Page != "" && !strings.HasPrefix(a.Page, "/") {
			return fmt.Errorf("%s: page %q must start with /", at, a.Page)
		}
		if _, err := path.Match(a.Page, "/"); err != nil {
			return fmt.Errorf("%s: page %q is not a valid pattern", at, a.Page)
		}
		if a.Code == "" && a.Tracker == "" && a.Page == "" && a.Pass == "" {
			return fmt.Errorf("%s: matches everything; name a code, tracker, page or pass", at)
		}
		if a.Until != "" {
			t, err := time.Parse("2006-01-02", a.Until)
			if err != nil {
				return fmt.Errorf("%s: until %q: use YYYY-MM-DD", at, a.Until)
			}
			a.until = t
		}
	}
	return nil
}

// CheckTrackers rejects tracker IDs the catalog doesn't know: a typo in an
// allow list would fail every tracker, and in a block list it would block
// nothing. Unclassified beacons are named "unclassified:<host>".
func (r *Rules) CheckTrackers(cat *Catalog) error {
	known := map[string]bool{}
	for _, t := range cat.Trackers {
		known[t.ID] = true
	}
	check := func(where string, ids []string) error {
		for _, id := range ids {
			if !known[id] && !strings.HasPrefix(id, "unclassified:") {
				return fmt.Errorf("rules: trackers.%s: unknown tracker %q (see pxta catalog)", where, id)
			}
		}
		return nil
	}
	if err := check("allow", r.Trackers.Allow); err != nil {
		return err
	}
	if err := check("block", r.Trackers.Block); err != nil {
		return err
	}
	for i, a := range r.Allow {
		if a.Tracker != "" && !known[a.Tracker] && !strings.HasPrefix(a.Tracker, "unclassified:") {
			return fmt.Errorf("rules: allow[%d]: unknown tracker %q (see pxta catalog)", i, a.Tracker)
		}
	}
	return nil
}

// Problem is one thing a check found wrong, or excused.
type Problem struct {
	Code     string `json:"code"`
	Severity string `json:"severity,omitempty"`
	Pass     string `json:"pass,omitempty"`
	Page     string `json:"page,omitempty"`
	Tracker  string `json:"tracker,omitempty"`
	Sentence string `json:"sentence"`
	Count    int    `json:"count,omitempty"`
	// AllowedBy is the reason of the allow entry that excused it.
	AllowedBy string `json:"allowed_by,omitempty"`
}

// CheckResult is the verdict on one audit.
type CheckResult struct {
	Site    string    `json:"site"`
	Pass    bool      `json:"pass"`
	Failed  []Problem `json:"failed"`
	Allowed []Problem `json:"allowed"`
	// Expired lists allow entries past their until date; they excused nothing.
	Expired []Allowance    `json:"expired_allowances,omitempty"`
	FailOn  string         `json:"fail_on"`
	Counts  map[string]int `json:"finding_counts"`
}

// Check judges an audit result against the rules.
func Check(res *Result, rules *Rules) *CheckResult {
	if rules == nil {
		rules = DefaultRules()
	}
	now := rules.now
	if now.IsZero() {
		now = time.Now()
	}
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	out := &CheckResult{Site: res.Site, FailOn: rules.FailOn, Failed: []Problem{}, Allowed: []Problem{}, Counts: map[string]int{}}
	var live []Allowance
	for _, a := range rules.Allow {
		if !a.until.IsZero() && today.After(a.until) {
			out.Expired = append(out.Expired, a)
			continue
		}
		live = append(live, a)
	}
	failCode := map[string]bool{}
	for _, c := range rules.FailCodes {
		failCode[c] = true
	}
	judge := func(p Problem) {
		for _, a := range live {
			if a.matches(p) {
				p.AllowedBy = a.Reason
				out.Allowed = append(out.Allowed, p)
				return
			}
		}
		out.Failed = append(out.Failed, p)
	}
	var analysis Analysis
	if res.Analysis != nil {
		analysis = *res.Analysis
	}
	for k, v := range analysis.Counts {
		out.Counts[k] = v
	}
	for _, f := range analysis.Findings {
		fails := failCode[f.Code]
		if !fails && rules.FailOn != "never" && f.Code != CodeTrackerPresent && sevRank[f.Severity] >= sevRank[rules.FailOn] {
			fails = true
		}
		if !fails {
			continue
		}
		judge(Problem{Code: f.Code, Severity: f.Severity, Pass: f.Pass, Page: f.Page, Tracker: f.Tracker,
			Sentence: f.Sentence, Count: f.Count})
	}
	allow := map[string]bool{}
	for _, id := range rules.Trackers.Allow {
		allow[id] = true
	}
	block := map[string]bool{}
	for _, id := range rules.Trackers.Block {
		block[id] = true
	}
	for _, t := range analysis.Trackers {
		where := firstPage(t)
		switch {
		case block[t.ID]:
			judge(Problem{Code: ProblemTrackerBlocked, Tracker: t.ID, Page: where,
				Sentence: fmt.Sprintf("%s is on the site%s, and the rules block it.", t.Name, onPage(where))})
		case len(allow) > 0 && !allow[t.ID]:
			judge(Problem{Code: ProblemTrackerNotAllowed, Tracker: t.ID, Page: where,
				Sentence: fmt.Sprintf("%s is on the site%s, and it isn't on the rules' list of allowed trackers.", t.Name, onPage(where))})
		}
	}
	if rules.RequireBanner && !res.Banner.Found && len(analysis.Trackers) > 0 {
		judge(Problem{Code: ProblemNoBanner, Sentence: "The site has trackers but PXTA found no consent banner."})
	}
	out.Pass = len(out.Failed) == 0
	return out
}

func firstPage(t TrackerUse) string {
	var pages []string
	for _, m := range []map[string][]string{t.Fired, t.Loaded} {
		for _, ps := range m {
			pages = append(pages, ps...)
		}
	}
	sort.Strings(pages)
	if len(pages) == 0 {
		return ""
	}
	return pages[0]
}

func onPage(p string) string {
	if p == "" {
		return ""
	}
	return " (first seen on " + p + ")"
}

func (a Allowance) matches(p Problem) bool {
	if a.Code != "" && a.Code != p.Code {
		return false
	}
	if a.Tracker != "" && a.Tracker != p.Tracker {
		return false
	}
	if a.Pass != "" && a.Pass != p.Pass {
		return false
	}
	if a.Page != "" {
		pg := p.Page
		if i := strings.IndexAny(pg, "?#"); i >= 0 {
			pg = pg[:i]
		}
		if pg == "" {
			return false
		}
		if ok, _ := path.Match(a.Page, pg); !ok && !globPrefix(a.Page, pg) {
			return false
		}
	}
	return true
}

// globPrefix lets a pattern ending in /* match deeper paths too: /blog/*
// covers /blog/2026/post.
func globPrefix(pattern, p string) bool {
	if !strings.HasSuffix(pattern, "/*") {
		return false
	}
	return strings.HasPrefix(p, strings.TrimSuffix(pattern, "*"))
}

// WriteText prints a human summary of a check.
func (c *CheckResult) WriteText(w io.Writer) {
	for _, p := range c.Failed {
		fmt.Fprintf(w, "  FAIL   %-6s %s\n", strings.ToUpper(sevOrDash(p.Severity)), p.Sentence)
	}
	for _, p := range c.Allowed {
		fmt.Fprintf(w, "  ALLOW  %-6s %s (allowed: %s)\n", strings.ToUpper(sevOrDash(p.Severity)), p.Sentence, p.AllowedBy)
	}
	for _, a := range c.Expired {
		fmt.Fprintf(w, "  NOTE   an allow entry expired on %s and no longer applies: %s\n", a.Until, a.Reason)
	}
	verdict := "pass"
	if !c.Pass {
		verdict = "fail"
	}
	fmt.Fprintf(w, "pxta check: %s, %d %s, %d allowed by the rules\n", verdict, len(c.Failed), plural2(len(c.Failed), "problem"), len(c.Allowed))
}

var hexRunRe = regexp.MustCompile(`(?i)\b[0-9a-f]{32}(?:[0-9a-f]{32})?\b`)

// PublicSentence is a sentence fit for places anyone with access to the CI
// run can read (annotations, job summaries): page queries are cut to "?...",
// email addresses other than the probe and 32- or 64-digit hashes become
// REDACTED. The full sentence stays in check.json and the report.
func PublicSentence(s string) string {
	words := strings.Split(s, " ")
	for i, w := range words {
		if strings.HasPrefix(w, "/") {
			if j := strings.IndexByte(w, '?'); j >= 0 {
				tail := ""
				if strings.HasSuffix(w, ",") {
					tail = ","
				}
				words[i] = w[:j] + "?..." + tail
			}
		}
	}
	s = strings.Join(words, " ")
	s = emailRe.ReplaceAllStringFunc(s, func(m string) string {
		if isEmail(m) && !isProbe(m) {
			return Redacted
		}
		return m
	})
	return hexRunRe.ReplaceAllStringFunc(s, func(m string) string {
		if isProbe(m) {
			return m
		}
		return Redacted
	})
}

// WriteGitHub prints GitHub Actions annotations, one per problem. Sentences
// go through PublicSentence.
func (c *CheckResult) WriteGitHub(w io.Writer) {
	for _, p := range c.Failed {
		title := "pxta " + p.Code
		if p.Tracker != "" {
			title += " (" + p.Tracker + ")"
		}
		fmt.Fprintf(w, "::error title=%s::%s\n", ghProperty(title), ghData(PublicSentence(p.Sentence)))
	}
	for _, p := range c.Allowed {
		fmt.Fprintf(w, "::notice title=%s::%s\n", ghProperty("pxta allowed "+p.Code), ghData(PublicSentence(p.Sentence)+" Allowed: "+p.AllowedBy))
	}
	for _, a := range c.Expired {
		fmt.Fprintf(w, "::warning title=pxta expired allowance::%s\n", ghData("Expired on "+a.Until+": "+a.Reason))
	}
}

// Markdown is a step summary. Sentences go through PublicSentence.
func (c *CheckResult) Markdown() string {
	var b strings.Builder
	verdict := "passed"
	if !c.Pass {
		verdict = "failed"
	}
	fmt.Fprintf(&b, "## PXTA check %s: %s\n\n", verdict, mdCell(c.Site))
	fmt.Fprintf(&b, "%d %s, %d allowed by the rules. Fails on %s and above.\n\n", len(c.Failed), plural2(len(c.Failed), "problem"), len(c.Allowed), c.FailOn)
	table := func(ps []Problem, allowed bool) {
		if allowed {
			b.WriteString("| Severity | Problem | Tracker | Pass | Allowed because |\n|---|---|---|---|---|\n")
		} else {
			b.WriteString("| Severity | Problem | Tracker | Pass |\n|---|---|---|---|\n")
		}
		for _, p := range ps {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |", sevOrDash(p.Severity), mdCell(PublicSentence(p.Sentence)), mdCell(p.Tracker), mdCell(p.Pass))
			if allowed {
				fmt.Fprintf(&b, " %s |", mdCell(p.AllowedBy))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	if len(c.Failed) > 0 {
		table(c.Failed, false)
	}
	if len(c.Allowed) > 0 {
		b.WriteString("### Allowed\n\n")
		table(c.Allowed, true)
	}
	for _, a := range c.Expired {
		fmt.Fprintf(&b, "- Expired allowance (%s): %s\n", mdCell(a.Until), mdCell(a.Reason))
	}
	return b.String()
}

func sevOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func plural2(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

func mdCell(s string) string {
	s = strings.NewReplacer("|", "\\|", "\n", " ", "\r", " ", "<", "&lt;", ">", "&gt;").Replace(s)
	if s == "" {
		return "-"
	}
	return s
}

// GitHub workflow command escaping.
func ghData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

func ghProperty(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(s)
}

// ReadResult loads a findings.json written by an audit.
func ReadResult(file string) (*Result, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var r Result
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	if r.Tool != "pxta" || r.Analysis == nil {
		return nil, fmt.Errorf("%s: not a PXTA findings.json", file)
	}
	return &r, nil
}
