package pxta

import (
	"fmt"
	"io"
	"net/url"
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
)

// DiffResult is what changed between two audits.
type DiffResult struct {
	Old      DiffSide          `json:"old"`
	New      DiffSide          `json:"new"`
	Warnings []string          `json:"warnings,omitempty"`
	Added    []DiffFinding     `json:"new_findings"`
	Removed  []DiffFinding     `json:"gone_findings"`
	Counted  []DiffFinding     `json:"count_changes,omitempty"`
	Skipped  []DiffFinding     `json:"not_compared,omitempty"`
	Trackers []TrackerChange   `json:"tracker_changes"`
	Banner   []string          `json:"banner_changes,omitempty"`
	Counts   map[string][2]int `json:"counts"` // severity -> old, new
	Changed  bool              `json:"changed"`
	FailOn   string            `json:"fail_on,omitempty"`
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
// and for leaks the rule plus the parameter that carried it. The value
// itself is left out for personal data, because client and session IDs
// differ in every run; it stays for sensitive pages and search terms,
// where the word is the finding.
func diffKey(f *Finding) string {
	k := f.Code + "|" + f.Pass + "|" + f.Page + "|" + f.Tracker
	for _, l := range f.Evidence.Highlight {
		switch l.Rule {
		case RuleSensitive, RuleSearch:
			k += "|" + l.Rule + "|" + strings.ToLower(l.Value)
		default:
			k += "|" + l.Rule + "|" + l.Key
		}
	}
	return k
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

// Diff compares two audits. failOn is a severity, "" (any change fails) or
// "never".
func Diff(old, cur *Result, failOn string) *DiffResult {
	d := &DiffResult{Old: side(old), New: side(cur), Counts: map[string][2]int{}, FailOn: failOn}
	if host(old.Site) != host(cur.Site) {
		d.Warnings = append(d.Warnings, fmt.Sprintf("The audits are of different sites (%s and %s); pages are compared by path.", old.Site, cur.Site))
	}
	if old.Redacted != cur.Redacted {
		d.Warnings = append(d.Warnings, "One audit was redacted and the other wasn't, so pages with personal data in their address won't match.")
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
		case !passIn(old, f.Pass) || (f.Page != "" && !oldSeen[f.Pass][f.Page] && !newPage(f.Page, oldSeen)):
			// The old audit ran this pass but didn't reach this page in it,
			// though it saw it in another pass: not a fair comparison.
			d.Skipped = append(d.Skipped, toDiff(f))
		default:
			d.Added = append(d.Added, toDiff(f))
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

	d.Trackers = trackerChanges(old, cur, comparable)
	d.Banner = bannerChanges(old.Banner, cur.Banner)
	for _, l := range [][]DiffFinding{d.Added, d.Removed, d.Skipped, d.Counted} {
		sortDiff(l)
	}

	d.Changed = len(d.Added) > 0 || len(d.Removed) > 0 || len(d.Trackers) > 0 || len(d.Banner) > 0
	switch failOn {
	case "":
		d.Fail = d.Changed
	case "never":
	default:
		for _, f := range d.Added {
			if sevRank[f.Severity] >= sevRank[failOn] {
				d.Fail = true
			}
		}
	}
	return d
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

func trackerChanges(old, cur *Result, comparable func(pass, page string) bool) []TrackerChange {
	oldSeen := visited(old)
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
	var out []TrackerChange
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
			var added, removed []string
			before, after := 0, 0
			for _, p := range o.Fired[pass] {
				if comparable(pass, p) {
					before++
					if !contains(c.Fired[pass], p) {
						removed = append(removed, p)
					}
				}
			}
			for _, p := range c.Fired[pass] {
				if comparable(pass, p) || newPage(p, oldSeen) {
					after++
					if !contains(o.Fired[pass], p) {
						added = append(added, p)
					}
				}
			}
			if len(added) == 0 && len(removed) == 0 {
				continue
			}
			sort.Strings(added)
			sort.Strings(removed)
			tc := TrackerChange{Tracker: id, Name: name, Pass: pass, Added: added, Removed: removed, OldPages: before, NewPages: after}
			who := capitalize(diffPhrase(id, name))
			when := whenPhrase(pass)
			switch {
			case before == 0:
				tc.Kind = TrackerStarted
				tc.Sentence = fmt.Sprintf("%s now sends data %s, on %s.", who, when, pageList(added))
			case after == 0:
				tc.Kind = TrackerStopped
				tc.Sentence = fmt.Sprintf("%s no longer sends data %s (it did on %s).", who, when, pageList(removed))
			case after >= before:
				tc.Kind = TrackerMore
				tc.Sentence = fmt.Sprintf("%s sends data %s on %d %s, up from %d (new: %s).", who, when, after, plural2(after, "page"), before, pageList(added))
			default:
				tc.Kind = TrackerFewer
				tc.Sentence = fmt.Sprintf("%s sends data %s on %d %s, down from %d (gone: %s).", who, when, after, plural2(after, "page"), before, pageList(removed))
			}
			if tc.Kind == TrackerMore && len(removed) > 0 {
				tc.Sentence = strings.TrimSuffix(tc.Sentence, ").") + "; gone: " + pageList(removed) + ")."
			}
			if tc.Kind == TrackerFewer && len(added) > 0 {
				tc.Sentence = strings.TrimSuffix(tc.Sentence, ").") + "; new: " + pageList(added) + ")."
			}
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

func bannerChanges(o, c Banner) []string {
	var out []string
	switch {
	case o.Found && !c.Found:
		out = append(out, fmt.Sprintf("The consent banner (%s) is gone.", PlatformName(o.Platform)))
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
		case op != "" && cp == "":
			out = append(out, fmt.Sprintf("Banner problem %s fixed (was: %s)", passPhrase[pass], op))
		}
	}
	return out
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
	fmt.Fprintf(w, "pxta diff: %s (%s) against %s (%s)\n", d.New.Site, orDash(d.New.Started), d.Old.Site, orDash(d.Old.Started))
	for _, s := range d.Warnings {
		fmt.Fprintf(w, "  warning: %s\n", s)
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
	c := t
	c.Added, c.Removed = pub(t.Added), pub(t.Removed)
	who := c.Name
	if strings.HasPrefix(c.Tracker, "unclassified:") {
		who = "an unrecognised tracker"
	}
	who = capitalize(who)
	when := whenPhrase(c.Pass)
	switch c.Kind {
	case TrackerStarted:
		return fmt.Sprintf("%s now sends data %s, on %s.", who, when, pageList(c.Added))
	case TrackerStopped:
		return fmt.Sprintf("%s no longer sends data %s (it did on %s).", who, when, pageList(c.Removed))
	default:
		s := fmt.Sprintf("%s sends data %s on %d %s, was %d", who, when, c.NewPages, plural2(c.NewPages, "page"), c.OldPages)
		if len(c.Added) > 0 {
			s += "; new: " + pageList(c.Added)
		}
		if len(c.Removed) > 0 {
			s += "; gone: " + pageList(c.Removed)
		}
		return s + "."
	}
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
		fmt.Fprintf(&b, "\n> %s\n", mdCell(strings.ReplaceAll(s, d.Old.Site, host(d.Old.Site))))
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
