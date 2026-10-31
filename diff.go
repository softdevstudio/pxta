package pxta

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// DiffFinding is one finding in a diff: the finding as the audit wrote it,
// and, for a finding in both audits, its count in the old one.
type DiffFinding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Pass     string `json:"pass"`
	Page     string `json:"page"`
	Tracker  string `json:"tracker"`
	Name     string `json:"tracker_name"`
	Sentence string `json:"sentence"`
	Count    int    `json:"count"`
	OldCount int    `json:"old_count,omitempty"`
}

// TrackerChange is a change in what one tracker did in one pass.
type TrackerChange struct {
	Tracker  string   `json:"tracker"`
	Name     string   `json:"tracker_name"`
	Pass     string   `json:"pass"`
	Kind     string   `json:"kind"` // see the Tracker* change kinds
	Added    []string `json:"pages_added,omitempty"`
	Removed  []string `json:"pages_removed,omitempty"`
	OldPages int      `json:"old_pages"`
	NewPages int      `json:"new_pages"`
	Sentence string   `json:"sentence"`
}

// Tracker change kinds. Like finding codes, they are a public interface.
const (
	TrackerStarted = "started" // sends data in a pass where it sent none before
	TrackerStopped = "stopped" // no longer sends data in that pass
	TrackerMore    = "more-pages"
	TrackerFewer   = "fewer-pages"
	TrackerMoved   = "other-pages" // as many pages as before, not the same ones
)

// DiffResult is what changed between two audits.
type DiffResult struct {
	Old      DiffSide          `json:"old"`
	New      DiffSide          `json:"new"`
	Warnings []string          `json:"warnings,omitempty"`
	Added    []DiffFinding     `json:"new_findings"`
	Removed  []DiffFinding     `json:"gone_findings"`
	Counted  []DiffFinding     `json:"count_changes"`
	Skipped  []DiffFinding     `json:"not_compared"`
	Trackers []TrackerChange   `json:"tracker_changes"`
	Banner   []string          `json:"banner_changes"`
	Coverage []string          `json:"coverage_problems"` // a pass or every page missing from the new audit
	Counts   map[string][2]int `json:"counts"`            // severity -> old, new
	Changed  bool              `json:"changed"`
	FailOn   string            `json:"fail_on,omitempty"`
	NewPages bool              `json:"new_pages_compared,omitempty"`
	Fail     bool              `json:"fail"`
}

// DiffSide describes one of the two audits.
type DiffSide struct {
	Site     string   `json:"site"`
	Version  string   `json:"pxta_version"`
	Started  string   `json:"started"`
	Pages    int      `json:"pages"`
	Passes   []string `json:"passes"`
	Redacted bool     `json:"redacted,omitempty"`
}

// diffKey tells findings apart across audits: code, pass, page, tracker,
// and for leaks the rule plus what identifies it without the value.
// Values are left out because client and session IDs differ in every run.
// A personal-data leak is told by the parameter that carried it, with batch
// line and array indices taken out (which line of a batched hit holds the
// email depends on timing); a sensitive page by its category ("finance:
// debt"), since the value is the full address or title and differs between
// staging and production; a search term by the term. Consent Mode
// mismatches are keyed without their leaks, as Analyze keys them.
func diffKey(f *Finding) string {
	k := f.Code + "|" + f.Pass + "|" + f.Page + "|" + f.Tracker
	if f.Code == CodeConsentModeMismatch || f.Code == CodeConsentModeGranted {
		return k
	}
	for _, l := range f.Evidence.Highlight {
		switch l.Rule {
		case RuleSensitive:
			k += "|" + l.Rule + "|" + strings.ToLower(l.Category)
		case RuleSearch:
			k += "|" + l.Rule + "|" + strings.ToLower(l.Value)
		default:
			k += "|" + l.Rule + "|" + paramShape(l.Key)
		}
	}
	return k
}

var (
	batchLineRe  = regexp.MustCompile(`(^|>)body\.\d+>`)
	arrayIndexRe = regexp.MustCompile(`\[\d+\]`)
)

// paramShape is a parameter name without the batch line and array indices
// decode.go adds. A GA4 hit carries the same parameters in its address or as
// a line of a batched body, so "dl", "body.1>dl" and "body.3>dl" are all
// "dl".
func paramShape(key string) string {
	key = batchLineRe.ReplaceAllString(key, "${1}")
	return arrayIndexRe.ReplaceAllString(key, "[]")
}

// visited lists the page paths an audit visited without an error, by pass,
// in the form findings use.
func visited(r *Result) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, v := range r.Pages {
		if v.Error != "" {
			continue
		}
		u := v.FinalURL
		if u == "" || u == "about:blank" {
			u = v.URL
		}
		if out[v.Pass] == nil {
			out[v.Pass] = map[string]bool{}
		}
		out[v.Pass][pagePath(u)] = true
	}
	return out
}

func side(r *Result) DiffSide {
	pages := map[string]bool{}
	for _, v := range r.Pages {
		pages[v.URL] = true
	}
	s := DiffSide{Site: r.Site, Version: r.Version, Pages: len(pages), Passes: r.Passes, Redacted: r.Redacted}
	if !r.Started.IsZero() {
		s.Started = r.Started.UTC().Format("2006-01-02 15:04 UTC")
	}
	return s
}

func toDiff(f *Finding) DiffFinding {
	return DiffFinding{Code: f.Code, Severity: f.Severity, Pass: f.Pass, Page: f.Page, Tracker: f.Tracker, Name: f.Name,
		Sentence: f.Sentence, Count: f.Count}
}

// DiffOptions shape a comparison.
type DiffOptions struct {
	// FailOn is a severity, "" (any change fails) or "never".
	FailOn string
	// NewPages counts findings on pages no pass of the old audit reached as
	// new. Off by default: a crawl that reaches one more page, or a page that
	// timed out last time, would otherwise look like a change.
	NewPages bool
}

// ErrRedactionMix is returned for a redacted and an unredacted audit: their
// pages don't match, and the diff would carry the unredacted one's data
// next to the redacted one's.
var ErrRedactionMix = errors.New("one audit was redacted and the other wasn't; compare two redacted or two unredacted audits")

// Diff compares two audits.
func Diff(old, cur *Result, opt DiffOptions) (*DiffResult, error) {
	if old.Redacted != cur.Redacted {
		return nil, ErrRedactionMix
	}
	failOn := opt.FailOn
	d := &DiffResult{Old: side(old), New: side(cur), Counts: map[string][2]int{}, FailOn: failOn, NewPages: opt.NewPages,
		Added: []DiffFinding{}, Removed: []DiffFinding{}, Counted: []DiffFinding{}, Skipped: []DiffFinding{},
		Trackers: []TrackerChange{}, Banner: []string{}, Coverage: []string{}, Warnings: []string{}}
	if host(old.Site) != host(cur.Site) {
		d.Warnings = append(d.Warnings, fmt.Sprintf("The audits are of different sites (%s and %s); pages are compared by path.", host(old.Site), host(cur.Site)))
	}
	if old.Catalog != cur.Catalog && old.Catalog != "" && cur.Catalog != "" {
		d.Warnings = append(d.Warnings, fmt.Sprintf("The tracker catalogs differ (%s and %s), so some changes may come from PXTA, not the site.", old.Catalog, cur.Catalog))
	}
	oldSeen, curSeen := visited(old), visited(cur)
	passIn := func(r *Result, p string) bool {
		for _, x := range r.Passes {
			if x == p {
				return true
			}
		}
		return false
	}
	// comparable: the page was visited in this pass by both audits.
	comparable := func(pass, page string) bool {
		if !passIn(old, pass) || !passIn(cur, pass) {
			return false
		}
		if page == "" {
			return true
		}
		return oldSeen[pass][page] && curSeen[pass][page]
	}

	index := func(r *Result) (map[string]*Finding, []string) {
		m := map[string]*Finding{}
		var order []string
		for _, f := range r.Findings {
			if f.Code == CodeTrackerPresent {
				continue
			}
			k := diffKey(f)
			if e := m[k]; e != nil {
				c := *e
				c.Count += f.Count
				m[k] = &c
				continue
			}
			m[k] = f
			order = append(order, k)
		}
		return m, order
	}
	oldF, oldOrder := index(old)
	curF, curOrder := index(cur)
	for _, k := range curOrder {
		f := curF[k]
		o := oldF[k]
		switch {
		case o != nil:
			if o.Count != f.Count {
				df := toDiff(f)
				df.OldCount = o.Count
				d.Counted = append(d.Counted, df)
			}
		case comparable(f.Pass, f.Page) || (opt.NewPages && passIn(old, f.Pass) && newPage(f.Page, oldSeen)):
			d.Added = append(d.Added, toDiff(f))
		default:
			// The old audit didn't reach this page in this pass, or didn't
			// run the pass: not a fair comparison.
			d.Skipped = append(d.Skipped, toDiff(f))
		}
	}
	for _, k := range oldOrder {
		f := oldF[k]
		if curF[k] != nil {
			continue
		}
		if comparable(f.Pass, f.Page) {
			d.Removed = append(d.Removed, toDiff(f))
		} else {
			d.Skipped = append(d.Skipped, toDiff(f))
		}
	}
	for _, f := range old.Findings {
		if f.Code != CodeTrackerPresent {
			c := d.Counts[f.Severity]
			c[0]++
			d.Counts[f.Severity] = c
		}
	}
	for _, f := range cur.Findings {
		if f.Code != CodeTrackerPresent {
			c := d.Counts[f.Severity]
			c[1]++
			d.Counts[f.Severity] = c
		}
	}

	newOK := func(pass, page string) bool {
		return opt.NewPages && passIn(old, pass) && newPage(page, oldSeen)
	}
	d.Trackers = trackerChanges(old, cur, comparable, newOK)
	var bannerWorse bool
	d.Banner, bannerWorse = bannerChanges(old.Banner, cur.Banner)
	// Coverage: a pass the old audit ran that the new one didn't, or a new
	// audit that visited no page, hides every change it would have shown.
	for _, p := range old.Passes {
		if !passIn(cur, p) {
			d.Coverage = append(d.Coverage, fmt.Sprintf("The %s pass ran in the old audit but not in the new one, so nothing %s was compared.", passName(p), passPhrase[p]))
		}
	}
	n := 0
	for _, pages := range curSeen {
		n += len(pages)
	}
	if n == 0 {
		d.Coverage = append(d.Coverage, "The new audit visited no page without an error.")
	}
	for _, l := range [][]DiffFinding{d.Added, d.Removed, d.Skipped, d.Counted} {
		sortDiff(l)
	}

	d.Changed = len(d.Added) > 0 || len(d.Removed) > 0 || len(d.Trackers) > 0 || len(d.Banner) > 0 || len(d.Coverage) > 0
	switch failOn {
	case "":
		d.Fail = d.Changed
	case "never":
	default:
		// A lost pass, an audit that saw nothing, or a banner that's gone or
		// can no longer be answered fail at any threshold: they are consent
		// regressions, or they hide the findings that would show one.
		d.Fail = len(d.Coverage) > 0 || bannerWorse
		for _, f := range d.Added {
			if sevRank[f.Severity] >= sevRank[failOn] || f.Code == CodeBannerNotHandled {
				d.Fail = true
			}
		}
	}
	return d, nil
}

func passName(p string) string {
	switch p {
	case PassNone:
		return "no-answer"
	case PassNoBanner:
		return "no-banner"
	}
	return p
}

// newPage reports whether no pass of the old audit visited the page: a
// page the site didn't have, or the crawl didn't reach, before. Findings
// there are new.
func newPage(page string, seen map[string]map[string]bool) bool {
	for _, pages := range seen {
		if pages[page] {
			return false
		}
	}
	return true
}

func host(site string) string {
	u, err := url.Parse(site)
	if err != nil {
		return site
	}
	return strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
}

func trackerChanges(old, cur *Result, comparable func(pass, page string) bool, newOK func(pass, page string) bool) []TrackerChange {
	oldT := map[string]TrackerUse{}
	for _, t := range old.Trackers {
		oldT[t.ID] = t
	}
	curT := map[string]TrackerUse{}
	for _, t := range cur.Trackers {
		curT[t.ID] = t
	}
	ids := map[string]bool{}
	for id := range oldT {
		ids[id] = true
	}
	for id := range curT {
		ids[id] = true
	}
	passes := []string{PassNone, PassReject, PassAccept, PassNoBanner}
	out := []TrackerChange{}
	for id := range ids {
		o, c := oldT[id], curT[id]
		name := c.Name
		if name == "" {
			name = o.Name
		}
		for _, pass := range passes {
			if !comparable(pass, "") {
				continue
			}
			// Page lists hold only pages both audits visited (and, with
			// NewPages, pages new to the site); whether the tracker sent data
			// in the pass at all comes from the full lists.
			var added, removed []string
			for _, p := range o.Fired[pass] {
				if comparable(pass, p) && !contains(c.Fired[pass], p) {
					removed = append(removed, p)
				}
			}
			for _, p := range c.Fired[pass] {
				if (comparable(pass, p) || newOK(pass, p)) && !contains(o.Fired[pass], p) {
					added = append(added, p)
				}
			}
			if len(added) == 0 && len(removed) == 0 {
				continue
			}
			sort.Strings(added)
			sort.Strings(removed)
			before, after := len(o.Fired[pass]), len(c.Fired[pass])
			tc := TrackerChange{Tracker: id, Name: name, Pass: pass, Added: added, Removed: removed, OldPages: before, NewPages: after}
			switch {
			case before == 0:
				tc.Kind = TrackerStarted
			case after == 0:
				tc.Kind = TrackerStopped
			case len(added) > len(removed):
				tc.Kind = TrackerMore
			case len(added) < len(removed):
				tc.Kind = TrackerFewer
			default:
				tc.Kind = TrackerMoved
			}
			tc.Sentence = tc.describe(capitalize(diffPhrase(id, name)), tc.Added, tc.Removed)
			out = append(out, tc)
		}
	}
	rank := map[string]int{PassNone: 0, PassReject: 1, PassNoBanner: 2, PassAccept: 3}
	sort.Slice(out, func(i, j int) bool {
		if rank[out[i].Pass] != rank[out[j].Pass] {
			return rank[out[i].Pass] < rank[out[j].Pass]
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// describe words a tracker change; who is the tracker as a sentence opens.
func (t TrackerChange) describe(who string, added, removed []string) string {
	when := whenPhrase(t.Pass)
	switch t.Kind {
	case TrackerStarted:
		return fmt.Sprintf("%s now sends data %s, on %s.", who, when, pageList(added))
	case TrackerStopped:
		return fmt.Sprintf("%s no longer sends data %s (it did on %s).", who, when, pageList(removed))
	}
	s := fmt.Sprintf("%s sends data %s on %d %s, was %d", who, when, t.NewPages, plural2(t.NewPages, "page"), t.OldPages)
	if len(added) > 0 {
		s += "; new: " + pageList(added)
	}
	if len(removed) > 0 {
		s += "; gone: " + pageList(removed)
	}
	return s + "."
}

// diffPhrase names a tracker in a sentence, as Analyze does: "the Meta
// Pixel", "Google Analytics 4", "a request to cdn.example".
func diffPhrase(id, name string) string {
	if strings.HasPrefix(id, "unclassified:") {
		return trackerPhrase(name, nil)
	}
	return trackerPhrase(name, &Tracker{ID: id})
}

func pageList(pages []string) string {
	if len(pages) > 4 {
		return strings.Join(pages[:4], ", ") + fmt.Sprintf(" and %d more", len(pages)-4)
	}
	return strings.Join(pages, ", ")
}

// bannerChanges lists what changed about the banner; worse is true when
// the banner is gone or PXTA can no longer answer it in a pass.
func bannerChanges(o, c Banner) (out []string, worse bool) {
	out = []string{}
	switch {
	case o.Found && !c.Found:
		out = append(out, fmt.Sprintf("The consent banner (%s) is gone.", PlatformName(o.Platform)))
		worse = true
	case !o.Found && c.Found:
		out = append(out, fmt.Sprintf("A consent banner (%s) appeared.", PlatformName(c.Platform)))
	case o.Found && c.Found && o.Platform != c.Platform:
		out = append(out, fmt.Sprintf("The consent banner changed from %s to %s.", PlatformName(o.Platform), PlatformName(c.Platform)))
	}
	for _, pass := range []string{PassNone, PassReject, PassAccept} {
		op, cp := o.Problems[pass], c.Problems[pass]
		switch {
		case op == "" && cp != "":
			out = append(out, fmt.Sprintf("New banner problem %s: %s", passPhrase[pass], cp))
			worse = true
		case op != "" && cp == "":
			out = append(out, fmt.Sprintf("Banner problem %s fixed (was: %s)", passPhrase[pass], op))
		}
	}
	return out, worse
}

func sortDiff(l []DiffFinding) {
	sort.SliceStable(l, func(i, j int) bool {
		if sevRank[l[i].Severity] != sevRank[l[j].Severity] {
			return sevRank[l[i].Severity] > sevRank[l[j].Severity]
		}
		if l[i].Page != l[j].Page {
			return l[i].Page < l[j].Page
		}
		return l[i].Code < l[j].Code
	})
}

func (f DiffFinding) problem() Problem {
	return Problem{Code: f.Code, Severity: f.Severity, Pass: f.Pass, Page: f.Page, Tracker: f.Tracker, Name: f.Name, Count: f.Count}
}

// WriteText prints the diff for a person. With public set (a CI log),
// findings are described from their fields, never their sentences.
func (d *DiffResult) WriteText(w io.Writer, public bool) {
	say := func(f DiffFinding) string {
		if public {
			return PublicLine(f.problem())
		}
		return f.Sentence
	}
	newSite, oldSite := d.New.Site, d.Old.Site
	if public {
		// A start address can carry a query; the log gets the host.
		newSite, oldSite = host(newSite), host(oldSite)
	}
	fmt.Fprintf(w, "pxta diff: %s (%s) against %s (%s)\n", newSite, orDash(d.New.Started), oldSite, orDash(d.Old.Started))
	for _, s := range d.Warnings {
		fmt.Fprintf(w, "  warning: %s\n", s)
	}
	for _, s := range d.Coverage {
		fmt.Fprintf(w, "  not compared: %s\n", s)
	}
	section := func(title string, l []DiffFinding, extra func(DiffFinding) string) {
		if len(l) == 0 {
			return
		}
		fmt.Fprintf(w, "\n%s (%d)\n", title, len(l))
		for _, f := range l {
			s := say(f)
			if extra != nil {
				s += extra(f)
			}
			fmt.Fprintf(w, "  %-6s %s\n", strings.ToUpper(sevOrDash(f.Severity)), s)
		}
	}
	section("New findings", d.Added, nil)
	section("Gone findings", d.Removed, nil)
	if len(d.Trackers) > 0 {
		fmt.Fprintf(w, "\nTracker changes (%d)\n", len(d.Trackers))
		for _, t := range d.Trackers {
			s := t.Sentence
			if public {
				s = t.publicSentence()
			}
			fmt.Fprintf(w, "  %s\n", s)
		}
	}
	if len(d.Banner) > 0 {
		fmt.Fprintf(w, "\nBanner changes (%d)\n", len(d.Banner))
		for _, s := range d.Banner {
			if public {
				s = publicBanner(s)
			}
			fmt.Fprintf(w, "  %s\n", s)
		}
	}
	if !public {
		section("Same finding, different count", d.Counted, func(f DiffFinding) string { return fmt.Sprintf(" (%d, was %d)", f.Count, f.OldCount) })
		section("Not compared (page or pass not in both audits)", d.Skipped, nil)
	} else if len(d.Skipped) > 0 {
		fmt.Fprintf(w, "\n%d %s not compared: page or pass not in both audits.\n", len(d.Skipped), plural2(len(d.Skipped), "finding"))
	}
	verdict := "no change"
	if d.Changed {
		verdict = fmt.Sprintf("%d new, %d gone, %d tracker %s, %d banner %s", len(d.Added), len(d.Removed),
			len(d.Trackers), plural2(len(d.Trackers), "change"), len(d.Banner), plural2(len(d.Banner), "change"))
		if len(d.Coverage) > 0 {
			verdict += fmt.Sprintf(", %d coverage %s", len(d.Coverage), plural2(len(d.Coverage), "problem"))
		}
	}
	fmt.Fprintf(w, "\npxta diff: %s\n", verdict)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// publicSentence describes a tracker change without the pages' queries or
// anything else the site sent.
func (t TrackerChange) publicSentence() string {
	pub := func(l []string) []string {
		out := make([]string, len(l))
		for i, p := range l {
			out[i] = PublicPath(p)
		}
		return out
	}
	who := diffPhrase(t.Tracker, t.Name)
	if strings.HasPrefix(t.Tracker, "unclassified:") {
		who = "an unrecognised tracker"
	}
	return t.describe(capitalize(who), pub(t.Added), pub(t.Removed))
}

// publicBanner keeps the banner change and drops the problem text, which
// can quote the page.
func publicBanner(s string) string {
	if i := strings.Index(s, ": "); i >= 0 && (strings.HasPrefix(s, "New banner problem") || strings.HasPrefix(s, "Banner problem")) {
		return s[:i] + "."
	}
	return s
}

// WriteGitHub prints an annotation per new finding (error at or above
// fail-on, warning otherwise) and a notice per gone finding.
func (d *DiffResult) WriteGitHub(w io.Writer) {
	for _, s := range d.Coverage {
		fmt.Fprintf(w, "::error title=pxta diff coverage::%s\n", ghData(s))
	}
	for _, s := range d.Banner {
		if strings.HasPrefix(s, "New banner problem") || strings.HasSuffix(s, "is gone.") {
			fmt.Fprintf(w, "::error title=pxta diff banner::%s\n", ghData(publicBanner(s)))
		}
	}
	for _, f := range d.Added {
		level := "warning"
		if d.FailOn == "" || (d.FailOn != "never" && sevRank[f.Severity] >= sevRank[d.FailOn]) {
			level = "error"
		}
		title := "pxta diff new " + f.Code
		if f.Tracker != "" {
			title += " (" + PublicTracker(f.Tracker) + ")"
		}
		fmt.Fprintf(w, "::%s title=%s::%s\n", level, ghProperty(title), ghData(PublicLine(f.problem())))
	}
	for _, f := range d.Removed {
		fmt.Fprintf(w, "::notice title=%s::%s\n", ghProperty("pxta diff gone "+f.Code), ghData(PublicLine(f.problem())))
	}
	for _, t := range d.Trackers {
		if t.Kind == TrackerStarted && t.Pass != PassAccept {
			fmt.Fprintf(w, "::warning title=%s::%s\n", ghProperty("pxta diff tracker "+PublicTracker(t.Tracker)), ghData(t.publicSentence()))
		}
	}
}

// Markdown is a job summary built from public lines only.
func (d *DiffResult) Markdown() string {
	var b strings.Builder
	if d.Changed {
		fmt.Fprintf(&b, "## PXTA diff: %d new, %d gone\n\n", len(d.Added), len(d.Removed))
	} else {
		b.WriteString("## PXTA diff: no change\n\n")
	}
	fmt.Fprintf(&b, "Against the audit of %s.\n", orDash(d.Old.Started))
	for _, s := range d.Warnings {
		fmt.Fprintf(&b, "\n> %s\n", mdCell(s))
	}
	for _, s := range d.Coverage {
		fmt.Fprintf(&b, "\n> **Not compared:** %s\n", mdCell(s))
	}
	table := func(title string, l []DiffFinding) {
		if len(l) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n### %s\n\n| Severity | Problem | Tracker | Pass |\n|---|---|---|---|\n", title)
		for _, f := range l {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", sevOrDash(f.Severity), mdCell(PublicLine(f.problem())), mdCell(PublicTracker(f.Tracker)), mdCell(f.Pass))
		}
	}
	table("New findings", d.Added)
	table("Gone findings", d.Removed)
	if len(d.Trackers) > 0 {
		b.WriteString("\n### Tracker changes\n\n")
		for _, t := range d.Trackers {
			fmt.Fprintf(&b, "- %s\n", mdCell(t.publicSentence()))
		}
	}
	if len(d.Banner) > 0 {
		b.WriteString("\n### Banner changes\n\n")
		for _, s := range d.Banner {
			fmt.Fprintf(&b, "- %s\n", mdCell(publicBanner(s)))
		}
	}
	if len(d.Skipped) > 0 {
		fmt.Fprintf(&b, "\n%d %s not compared: page or pass not in both audits.\n", len(d.Skipped), plural2(len(d.Skipped), "finding"))
	}
	return b.String()
}
