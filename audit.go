package pxta

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Options controls an audit.
type Options struct {
	StartURL     string
	MaxPages     int           // pages to visit, default 20
	MaxDepth     int           // link depth from the start page, default 3
	Sitemap      string        // optional sitemap address to seed the crawl
	PageWait     time.Duration // longest time on one page, default 15s
	Idle         time.Duration // a page is done after this long without a new request, default 2s
	BannerWait   time.Duration // how long to look for a consent banner, default 6s
	Delay        time.Duration // pause between page loads, default 1s
	IgnoreRobots bool
	FillForms    bool // type ProbeEmail into email fields, default on in the CLI
	KnownEmails  []string
	Passes       []string // which of none, reject, accept to run; default all
	OutDir       string
	Resume       bool
	BrowserPath  string
	BrowserArgs  []string     // extra Chrome flags (the tests map tracker hosts to fixtures)
	HTTPClient   *http.Client // robots.txt and sitemaps
	Catalog      *Catalog
	Log          io.Writer
	ReproBase    string // the command shown in findings to rerun one page
	// Redact replaces the personal values in the written report with
	// REDACTED, and fails the audit if any is left in the files.
	Redact bool
	// The tests use these.
	OnPage func(pass string, page int) // called after each page is recorded
}

// Result is a finished audit.
type Result struct {
	Tool        string    `json:"tool"`
	Version     string    `json:"version"`
	Catalog     string    `json:"catalog"`
	Site        string    `json:"site"`
	Started     time.Time `json:"started"`
	Finished    time.Time `json:"finished"`
	Browser     string    `json:"browser"`
	UserAgent   string    `json:"user_agent"`
	Banner      Banner    `json:"banner"`
	Passes      []string  `json:"passes"`
	Pages       []Visit   `json:"pages"`
	Emails      []string  `json:"known_emails,omitempty"`
	FilledForms bool      `json:"filled_forms"`
	Settings    Settings  `json:"settings"`
	Restarts    int       `json:"browser_restarts"`
	HARSHA256   string    `json:"har_sha256,omitempty"`
	Redacted    bool      `json:"redacted,omitempty"`
	*Analysis
	requests []Request
	redactor *redactor
}

// Banner is what PXTA found and did about the consent banner.
type Banner struct {
	Found    bool              `json:"found"`
	Platform string            `json:"platform,omitempty"`
	Frame    string            `json:"frame,omitempty"`
	Actions  map[string]string `json:"actions,omitempty"` // pass -> what PXTA did
	Problems map[string]string `json:"problems,omitempty"`
}

// Settings records the options that shape the results.
type Settings struct {
	MaxPages     int    `json:"max_pages"`
	MaxDepth     int    `json:"max_depth"`
	PageWait     string `json:"page_wait"`
	Idle         string `json:"idle"`
	BannerWait   string `json:"banner_wait"`
	RespectRobot bool   `json:"respect_robots"`
	Sitemap      string `json:"sitemap,omitempty"`
}

func (o *Options) defaults() {
	if o.MaxPages <= 0 {
		o.MaxPages = 20
	}
	if o.MaxDepth <= 0 {
		o.MaxDepth = 3
	}
	if o.PageWait <= 0 {
		o.PageWait = 15 * time.Second
	}
	if o.Idle <= 0 {
		o.Idle = 2 * time.Second
	}
	if o.BannerWait <= 0 {
		o.BannerWait = 6 * time.Second
	}
	if o.Delay < 0 {
		o.Delay = 0
	}
	if len(o.Passes) == 0 {
		o.Passes = []string{PassNone, PassReject, PassAccept}
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 20 * time.Second}
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
}

type auditor struct {
	o        Options
	cat      *Catalog
	b        *Browser
	ua       string
	origin   *url.URL // the address the audit was started with
	base     *url.URL // where the start page landed after redirects; links are kept relative to it
	robots   *Robots
	emails   *Emails
	res      *Result
	state    *checkpoint
	restarts int
}

// checkpoint is written after every page, so an interrupted audit can go on
// with --resume.
type checkpoint struct {
	Site     string          `json:"site"`
	Version  string          `json:"version"`
	Pages    []string        `json:"pages"`
	Depths   []int           `json:"depths"`
	Done     map[string]int  `json:"done"` // pass -> pages finished
	Banner   Banner          `json:"banner"`
	Visits   []Visit         `json:"visits"`
	Emails   []string        `json:"emails"`
	Started  time.Time       `json:"started"`
	Restarts int             `json:"restarts"`
	Passes   []string        `json:"passes"`
	Frontier []frontierEntry `json:"frontier,omitempty"`
	Base     string          `json:"base,omitempty"`
}

type frontierEntry struct {
	URL   string `json:"url"`
	Depth int    `json:"depth"`
}

func (a *auditor) logf(format string, args ...any) { fmt.Fprintf(a.o.Log, format+"\n", args...) }

// Audit runs a full audit and writes report.html, findings.json and
// requests.har to o.OutDir.
func Audit(ctx context.Context, o Options) (*Result, error) {
	res, err := audit(ctx, o)
	if err != nil && o.Redact && ctx.Err() == nil && o.OutDir != "" {
		// A redacted audit that failed leaves nothing unredacted behind: not
		// the report files, and not the working files that hold every raw
		// request. An interrupted one keeps them, so --resume works.
		for _, f := range []string{"findings.json", "report.html", "requests.har", "state.json", "requests.jsonl"} {
			os.Remove(filepath.Join(o.OutDir, f))
		}
	}
	return res, err
}

func audit(ctx context.Context, o Options) (*Result, error) {
	o.defaults()
	start, err := url.Parse(o.StartURL)
	if err != nil || (start.Scheme != "http" && start.Scheme != "https") || start.Host == "" {
		return nil, fmt.Errorf("start address must be a full http(s) URL, got %q", o.StartURL)
	}
	if start.Path == "" {
		start.Path = "/"
	}
	cat := o.Catalog
	if cat == nil {
		if cat, err = LoadCatalog(""); err != nil {
			return nil, err
		}
	}
	if o.OutDir == "" {
		o.OutDir = "pxta-report"
	}
	if err := os.MkdirAll(o.OutDir, 0o755); err != nil {
		return nil, err
	}
	a := &auditor{o: o, cat: cat, origin: start, base: start, emails: NewEmails()}
	for _, e := range o.KnownEmails {
		a.emails.Add(e)
	}
	if o.FillForms {
		a.emails.Add(ProbeEmail)
	}
	a.res = &Result{Tool: "pxta", Version: Version, Catalog: CatalogVersion, Site: start.String(), Started: time.Now().UTC(),
		FilledForms: o.FillForms, Settings: Settings{MaxPages: o.MaxPages, MaxDepth: o.MaxDepth, PageWait: o.PageWait.String(),
			Idle: o.Idle.String(), BannerWait: o.BannerWait.String(), RespectRobot: !o.IgnoreRobots, Sitemap: o.Sitemap}}
	a.state = &checkpoint{Site: start.String(), Version: Version, Done: map[string]int{}, Started: a.res.Started}
	reqFile := filepath.Join(o.OutDir, "requests.jsonl")
	if o.Resume {
		if err := a.loadCheckpoint(); err != nil {
			return nil, fmt.Errorf("resume: %w", err)
		}
	} else {
		os.Remove(reqFile)
	}
	rf, err := os.OpenFile(reqFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	defer rf.Close()
	if err := a.launch(ctx); err != nil {
		return nil, err
	}
	defer func() { a.b.Kill() }()
	a.res.Browser, a.res.UserAgent = a.b.Version, a.ua
	if !o.IgnoreRobots {
		a.robots = fetchRobots(ctx, o.HTTPClient, start, a.ua)
		if !a.robots.Allowed(start) {
			return nil, fmt.Errorf("robots.txt on %s asks crawlers not to load %s (use --ignore-robots on your own site)", start.Host, start.Path)
		}
	}
	if !o.Resume {
		a.state.Frontier = []frontierEntry{{URL: start.String(), Depth: 0}}
		if o.Sitemap != "" {
			urls, err := fetchSitemap(ctx, o.HTTPClient, o.Sitemap, a.ua, o.MaxPages*5)
			if err != nil {
				a.logf("sitemap: %v (crawling links only)", err)
			}
			for _, u := range urls {
				if n, ok := normalizeLink(u, start); ok {
					a.state.Frontier = append(a.state.Frontier, frontierEntry{URL: n, Depth: 1})
				}
			}
		}
	}
	w := bufio.NewWriter(rf)
	defer w.Flush()
	record := func(rs []Request) error {
		for _, r := range rs {
			b, err := json.Marshal(r)
			if err != nil {
				return err
			}
			w.Write(b)
			w.WriteByte('\n')
		}
		return w.Flush()
	}
	// The first pass leaves the banner alone and discovers the pages; the
	// others visit the same pages after rejecting or accepting.
	first := PassNone
	if err := a.runPass(ctx, first, true, record); err != nil {
		return nil, err
	}
	passes := []string{PassNoBanner}
	if a.state.Banner.Found {
		// The unanswered pass always runs, since it finds the pages, but it
		// is reported only when it was asked for.
		passes = nil
		for _, p := range o.Passes {
			if p == PassNone {
				passes = append(passes, PassNone)
			}
		}
		for _, p := range o.Passes {
			if p == PassReject || p == PassAccept {
				if err := a.runPass(ctx, p, false, record); err != nil {
					return nil, err
				}
				if _, bad := a.state.Banner.Problems[p]; !bad {
					passes = append(passes, p)
				}
			}
		}
	}
	w.Flush()
	reqs, err := readRequests(reqFile)
	if err != nil {
		return nil, err
	}
	if !a.state.Banner.Found {
		for i := range reqs {
			reqs[i].Pass = PassNoBanner
		}
		for i := range a.state.Visits {
			a.state.Visits[i].Pass = PassNoBanner
		}
	}
	// Leave out the requests and visits of passes that aren't reported: one
	// the operator didn't ask for, or one whose consent choice failed.
	keep := map[string]bool{}
	for _, p := range passes {
		keep[p] = true
	}
	kr := reqs[:0]
	for _, r := range reqs {
		if keep[r.Pass] {
			kr = append(kr, r)
		}
	}
	reqs = kr
	var kv []Visit
	for _, v := range a.state.Visits {
		if keep[v.Pass] {
			kv = append(kv, v)
		}
	}
	a.state.Visits = kv
	a.res.Passes = passes
	a.res.Banner = a.state.Banner
	a.res.Pages = a.state.Visits
	a.res.Restarts = a.state.Restarts
	a.res.requests = reqs
	var rd *redactor
	if o.Redact {
		rd = newRedactor(a.res, reqs, a.emails, a.cat)
		a.res.Analysis = analyze(a.cat, a.state.Visits, reqs, a.emails, o.ReproBase, rd.url)
	} else {
		a.res.Analysis = Analyze(a.cat, a.state.Visits, reqs, a.emails, o.ReproBase)
	}
	for p, msg := range a.state.Banner.Problems {
		a.res.Findings = append(a.res.Findings, &Finding{Code: CodeBannerNotHandled, Severity: SevInfo, Pass: p,
			Sentence: fmt.Sprintf("PXTA could not %s on the consent banner (%s), so the %s pass was left out.", p, msg, p)})
		a.res.Counts[SevInfo]++
	}
	sortFindings(a.res.Findings)
	a.res.Emails = a.emails.List()
	a.res.Finished = time.Now().UTC()
	if rd != nil {
		rd.apply(a.res, a.res.requests)
		a.res.redactor = rd
	}
	if err := WriteOutputs(a.res, o.OutDir); err != nil {
		return nil, err
	}
	if err := a.res.VerifyRedacted(o.OutDir); err != nil {
		// Audit removes the files: never a half-redacted report to share.
		return nil, err
	}
	// The working files go once the report is written; requests.har holds
	// every request.
	os.Remove(filepath.Join(o.OutDir, "state.json"))
	os.Remove(reqFile)
	return a.res, nil
}

func (a *auditor) launch(ctx context.Context) error {
	b, err := LaunchBrowser(ctx, LaunchOptions{Path: a.o.BrowserPath, ExtraArgs: a.o.BrowserArgs})
	if err != nil {
		return err
	}
	a.b = b
	a.ua = b.UserAgent + " pxta/" + Version + " (+https://pxta.com)"
	return nil
}

// relaunch replaces a browser that crashed.
func (a *auditor) relaunch(ctx context.Context) error {
	a.b.Kill()
	a.state.Restarts++
	a.logf("browser stopped; starting it again (restart %d)", a.state.Restarts)
	return a.launch(ctx)
}

// passContext opens a fresh profile for a pass and, for reject and accept,
// answers the banner on the start page first.
func (a *auditor) passContext(ctx context.Context, pass string) (string, error) {
	bc, err := a.b.newContext(ctx)
	if err != nil {
		return "", err
	}
	if pass != PassReject && pass != PassAccept {
		return bc, nil
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(parent, a.o.PageWait+2*a.o.BannerWait+20*time.Second)
	defer cancel()
	notHandled := func(msg string) (string, error) {
		if a.state.Banner.Problems == nil {
			a.state.Banner.Problems = map[string]string{}
		}
		a.state.Banner.Problems[pass] = msg
		return bc, errBannerNotHandled
	}
	t, err := a.b.openTab(ctx, bc, pass, -1, a.ua)
	if err != nil {
		return "", err
	}
	defer t.close()
	if err := t.navigate(ctx, a.origin.String()); err != nil {
		if parent.Err() == nil && a.b.Alive() {
			return notHandled("the start page did not load: " + err.Error())
		}
		return "", err
	}
	select {
	case <-t.rec.loaded:
	case <-time.After(a.o.PageWait):
	case <-ctx.Done():
		if parent.Err() != nil {
			return "", parent.Err()
		}
	}
	st := t.answerBanner(ctx, pass, a.o.BannerWait)
	if st.Done == "" {
		if parent.Err() != nil {
			return "", parent.Err()
		}
		if st.Error == "" {
			st.Error = "the banner did not answer in time"
		}
		return notHandled(st.Error)
	}
	if a.state.Banner.Actions == nil {
		a.state.Banner.Actions = map[string]string{}
	}
	a.state.Banner.Actions[pass] = st.Done
	// Let the platform store the choice before the recorded visits start.
	time.Sleep(time.Second)
	return bc, nil
}

var errBannerNotHandled = errors.New("banner not handled")

func (a *auditor) runPass(ctx context.Context, pass string, discover bool, record func([]Request) error) error {
	if !discover && a.state.Done[pass] >= len(a.state.Pages) && len(a.state.Pages) > 0 {
		return nil
	}
	a.logf("pass %s", pass)
	bc, err := a.passContext(ctx, pass)
	if errors.Is(err, errBannerNotHandled) {
		a.logf("  %s: %s", pass, a.state.Banner.Problems[pass])
		a.saveCheckpoint()
		return nil
	}
	if err != nil {
		if !a.b.Alive() {
			if err := a.relaunch(ctx); err != nil {
				return err
			}
			return a.runPass(ctx, pass, discover, record)
		}
		return err
	}
	defer func() { a.b.disposeContext(bc) }()
	for i := a.state.Done[pass]; ; i++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var pageURL string
		depth := 0
		if discover {
			// Take the next page from the frontier.
			for len(a.state.Frontier) > 0 && len(a.state.Pages) <= i {
				f := a.state.Frontier[0]
				a.state.Frontier = a.state.Frontier[1:]
				if contains(a.state.Pages, f.URL) {
					continue
				}
				if u, _ := url.Parse(f.URL); a.robots != nil && u != nil && !a.robots.Allowed(u) {
					continue
				}
				a.state.Pages = append(a.state.Pages, f.URL)
				a.state.Depths = append(a.state.Depths, f.Depth)
			}
			if i >= len(a.state.Pages) || i >= a.o.MaxPages {
				break
			}
		} else if i >= len(a.state.Pages) {
			break
		}
		pageURL, depth = a.state.Pages[i], a.state.Depths[i]
		if i > 0 && a.o.Delay > 0 {
			time.Sleep(a.o.Delay)
		}
		a.logf("  [%s %d/%d] %s", pass, i+1, len(a.state.Pages), pageURL)
		var v *Visit
		var reqs []Request
		for attempt := 0; attempt < 2; attempt++ {
			v, reqs, err = a.visit(ctx, bc, pass, i, pageURL, discover && i == 0)
			if err == nil || a.b.Alive() {
				break
			}
			// The browser died under this page: start again and redo the
			// pass's consent choice in the new browser.
			if err := a.relaunch(ctx); err != nil {
				return err
			}
			bc, err = a.passContext(ctx, pass)
			if errors.Is(err, errBannerNotHandled) {
				// The choice couldn't be made again in the new browser, so
				// the rest of this pass would not be what it says. Stop it;
				// the pass is left out of the report.
				a.logf("  %s: %s", pass, a.state.Banner.Problems[pass])
				a.saveCheckpoint()
				return nil
			}
			if err != nil {
				return err
			}
		}
		if v == nil {
			v = &Visit{Pass: pass, Page: i, URL: pageURL, Started: time.Now().UTC()}
		}
		if err != nil {
			v.Error = err.Error()
			a.logf("    error: %s", v.Error)
		}
		if err := record(reqs); err != nil {
			return err
		}
		v.Requests = len(reqs)
		a.state.Visits = append(a.state.Visits, *v)
		for _, e := range v.Emails {
			a.emails.Add(e)
		}
		if discover && i == 0 && v.FinalURL != "" {
			// The start address may redirect (example.com to
			// www.example.com, http to https): follow the site where it
			// landed.
			if f, err := url.Parse(v.FinalURL); err == nil && (f.Scheme == "http" || f.Scheme == "https") && bareHost(f.Hostname()) == bareHost(a.origin.Hostname()) {
				a.base = &url.URL{Scheme: f.Scheme, Host: f.Host}
				a.state.Base = a.base.String()
				if n, ok := normalizeLink(v.FinalURL, a.base); ok {
					a.state.Pages[0] = n
				}
			}
		}
		if discover && depth < a.o.MaxDepth {
			for _, l := range v.Links {
				if n, ok := normalizeLink(l, a.base); ok && !contains(a.state.Pages, n) {
					a.state.Frontier = append(a.state.Frontier, frontierEntry{URL: n, Depth: depth + 1})
				}
			}
		}
		a.state.Done[pass] = i + 1
		a.saveCheckpoint()
		if a.o.OnPage != nil {
			a.o.OnPage(pass, i)
		}
	}
	return nil
}

// visit loads one page in its own tab and records everything it sends.
func (a *auditor) visit(parent context.Context, bc, pass string, idx int, pageURL string, detect bool) (*Visit, []Request, error) {
	// Every browser call for this page shares one deadline, so a page that
	// stops answering (a script stuck in a loop, say) can't hold up the audit.
	ctx, cancel := context.WithTimeout(parent, a.o.PageWait+a.o.BannerWait+20*time.Second)
	defer cancel()
	v := &Visit{Pass: pass, Page: idx, URL: pageURL, Started: time.Now().UTC()}
	t, err := a.b.openTab(ctx, bc, pass, idx, a.ua)
	if err != nil {
		return v, nil, err
	}
	closed := false
	defer func() {
		if !closed {
			t.close()
		}
	}()
	deadline := time.Now().Add(a.o.PageWait)
	if err := t.navigate(ctx, pageURL); err != nil {
		return v, t.rec.requests(), err
	}
	select {
	case <-t.rec.loaded:
	case <-time.After(time.Until(deadline)):
	case <-ctx.Done():
		if parent.Err() != nil {
			return v, t.rec.requests(), parent.Err()
		}
		return v, t.rec.requests(), fmt.Errorf("%s did not finish loading in time", pageURL)
	case <-a.b.cdp.Done():
		return v, t.rec.requests(), ErrClosed
	}
	if detect {
		st := t.detectBanner(ctx, a.o.BannerWait)
		if st.Visible {
			a.state.Banner.Found = true
			a.state.Banner.Platform = st.Platform
			a.state.Banner.Frame = st.Frame
		}
	}
	t.rec.waitIdle(ctx, a.o.Idle, deadline)
	t.rec.setPhase("interact")
	// Scroll to the bottom in steps, so trackers that wait for scrolling fire.
	frame := frameCtx{session: t.session}
	for i := 1; i <= 4; i++ {
		_ = a.b.eval(ctx, frame, fmt.Sprintf("window.scrollTo(0, document.documentElement.scrollHeight*%d/4)", i), nil)
		time.Sleep(150 * time.Millisecond)
	}
	if a.o.FillForms {
		var n int
		_ = a.b.eval(ctx, frame, fillFormsJS+"("+jsString(ProbeEmail)+")", &n)
	}
	t.rec.waitIdle(ctx, a.o.Idle, deadline)
	var info struct {
		URL    string   `json:"url"`
		Title  string   `json:"title"`
		Links  []string `json:"links"`
		Emails []string `json:"emails"`
	}
	if err := a.b.eval(ctx, frame, pageInfoJS, &info); err == nil {
		v.FinalURL, v.Title, v.Links, v.Emails = info.URL, info.Title, info.Links, info.Emails
	}
	if !a.b.Alive() {
		return v, t.rec.requests(), ErrClosed
	}
	t.leave(ctx, 800*time.Millisecond)
	t.close()
	closed = true
	return v, t.rec.requests(), nil
}

func jsString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (a *auditor) saveCheckpoint() {
	a.state.Emails = a.emails.List()
	a.state.Passes = a.o.Passes
	b, err := json.MarshalIndent(a.state, "", "  ")
	if err != nil {
		return
	}
	p := filepath.Join(a.o.OutDir, "state.json")
	tmp := p + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		os.Rename(tmp, p)
	}
}

func (a *auditor) loadCheckpoint() error {
	b, err := os.ReadFile(filepath.Join(a.o.OutDir, "state.json"))
	if err != nil {
		return fmt.Errorf("no unfinished audit in %s", a.o.OutDir)
	}
	var st checkpoint
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}
	if st.Site != a.origin.String() {
		return fmt.Errorf("%s holds an audit of %s, not %s", a.o.OutDir, st.Site, a.origin.String())
	}
	if st.Done == nil {
		st.Done = map[string]int{}
	}
	a.state = &st
	if b, err := url.Parse(st.Base); err == nil && st.Base != "" {
		a.base = b
	}
	a.res.Started = st.Started
	for _, e := range st.Emails {
		a.emails.Add(e)
	}
	// Requests of a page that was in progress when the audit stopped are
	// dropped; that page is visited again.
	reqFile := filepath.Join(a.o.OutDir, "requests.jsonl")
	reqs, _ := readRequests(reqFile)
	keep := reqs[:0]
	for _, r := range reqs {
		if r.Page < st.Done[r.Pass] {
			keep = append(keep, r)
		}
	}
	f, err := os.Create(reqFile)
	if err != nil {
		return err
	}
	defer f.Close()
	bw := bufio.NewWriter(f)
	for _, r := range keep {
		b, _ := json.Marshal(r)
		bw.Write(b)
		bw.WriteByte('\n')
	}
	return bw.Flush()
}

func readRequests(p string) ([]Request, error) {
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []Request
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r Request
		if json.Unmarshal([]byte(line), &r) == nil {
			out = append(out, r)
		}
	}
	return out, sc.Err()
}
