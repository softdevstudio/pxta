package pxta

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// needBrowser skips a test when no browser is installed, unless
// PXTA_REQUIRE_BROWSER is set (as in CI), where it fails instead.
func needBrowser(t *testing.T) {
	t.Helper()
	if _, err := FindBrowser(""); err != nil {
		if os.Getenv("PXTA_REQUIRE_BROWSER") != "" {
			t.Fatalf("browser required but not found: %v", err)
		}
		t.Skip("no browser installed: ", err)
	}
	if testing.Short() {
		t.Skip("browser tests are slow; skipped with -short")
	}
}

func auditFixture(t *testing.T, f *fixture, start string, mod func(*Options)) *Result {
	t.Helper()
	o := Options{StartURL: start, OutDir: t.TempDir(), MaxPages: 10, MaxDepth: 3, PageWait: 12 * time.Second,
		Idle: 800 * time.Millisecond, BannerWait: 4 * time.Second, Delay: 0, FillForms: true, IgnoreRobots: true,
		BrowserArgs: f.Args(), HTTPClient: f.Client(), Log: testLog{t}}
	if mod != nil {
		mod(&o)
	}
	// About four seconds a page per pass is plenty; long crawls get longer.
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute+time.Duration(o.MaxPages)*12*time.Second)
	defer cancel()
	r, err := Audit(ctx, o)
	if err != nil {
		t.Fatalf("audit %s: %v", start, err)
	}
	return r
}

type testLog struct{ t *testing.T }

func (l testLog) Write(p []byte) (int, error) {
	l.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// find returns the findings with this code, pass and tracker whose sentence
// contains every word in has.
func find(r *Result, code, pass, tracker string, has ...string) []*Finding {
	var out []*Finding
	for _, f := range r.Findings {
		if f.Code != code || (pass != "" && f.Pass != pass) || (tracker != "" && f.Tracker != tracker) {
			continue
		}
		ok := true
		for _, h := range has {
			if !strings.Contains(f.Sentence, h) {
				ok = false
			}
		}
		if ok {
			out = append(out, f)
		}
	}
	return out
}

func mustFind(t *testing.T, r *Result, code, pass, tracker string, has ...string) *Finding {
	t.Helper()
	fs := find(r, code, pass, tracker, has...)
	if len(fs) == 0 {
		dumpFindings(t, r)
		t.Fatalf("no %s finding for %s in pass %s containing %q", code, tracker, pass, has)
	}
	return fs[0]
}

func mustNotFind(t *testing.T, r *Result, code, pass, tracker string) {
	t.Helper()
	if fs := find(r, code, pass, tracker); len(fs) > 0 {
		dumpFindings(t, r)
		t.Fatalf("unexpected %s finding for %s in pass %s: %s", code, tracker, pass, fs[0].Sentence)
	}
}

func dumpFindings(t *testing.T, r *Result) {
	t.Helper()
	t.Logf("banner %+v, passes %v, browser %s", r.Banner, r.Passes, r.Browser)
	for _, p := range r.Pages {
		if p.Error != "" {
			t.Logf("  page %s %d %s: %s", p.Pass, p.Page, p.URL, p.Error)
		}
	}
	for _, f := range r.Findings {
		t.Logf("  [%s %s %s] %s", f.Severity, f.Pass, f.Code, f.Sentence)
	}
	for i, q := range r.requests {
		if i == 25 {
			break
		}
		t.Logf("  request %s/%d %s %s %s", q.Pass, q.Page, q.Target, q.Type, q.URL)
	}
	for _, p := range r.Pages {
		t.Logf("  page %s %d %s final=%q title=%q", p.Pass, p.Page, p.URL, p.FinalURL, p.Title)
	}
}

func fired(r *Result, tracker, pass string) bool {
	for _, u := range r.Trackers {
		if u.ID == tracker && len(u.Fired[pass]) > 0 {
			return true
		}
	}
	return false
}

func checkOutputs(t *testing.T, dir string) {
	t.Helper()
	for _, f := range []string{"report.html", "findings.json", "requests.har"} {
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil || st.Size() == 0 {
			t.Errorf("%s missing or empty", f)
		}
	}
	b, _ := os.ReadFile(filepath.Join(dir, "findings.json"))
	var j map[string]any
	if err := json.Unmarshal(b, &j); err != nil {
		t.Errorf("findings.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json")); err == nil {
		t.Error("state.json left behind after a finished audit")
	}
}

// The leaky shop: a OneTrust banner that changes nothing.
func TestBrowserShop(t *testing.T) {
	needBrowser(t)
	f := startFixtures(t)
	var out string
	r := auditFixture(t, f, "https://www.harborpine.test/", func(o *Options) { out = o.OutDir })
	checkOutputs(t, out)
	if !r.Banner.Found || r.Banner.Platform != "onetrust" {
		dumpFindings(t, r)
		for i, h := range f.Hits() {
			if i < 25 {
				t.Logf("  fixture hit %s", h)
			}
		}
		t.Fatalf("banner %+v", r.Banner)
	}
	if len(r.Passes) != 3 {
		t.Fatalf("passes %v", r.Passes)
	}
	if !strings.Contains(r.Banner.Actions[PassReject], "onetrust-reject-all-handler") {
		t.Errorf("reject action %q", r.Banner.Actions[PassReject])
	}
	mustFind(t, r, CodeTrackerBeforeConsent, PassNone, "meta-pixel", "PageView")
	mustFind(t, r, CodeTrackerAfterReject, PassReject, "meta-pixel")
	mustFind(t, r, CodeTrackerAfterReject, PassReject, "google-analytics-4")
	// The order address carries the customer's email.
	mustFind(t, r, CodePersonalData, PassNone, "meta-pixel", "/checkout/confirm", "an email address inside the page address")
	mustFind(t, r, CodePersonalData, PassReject, "pinterest-tag", "SHA-256 hash of the email address jane@example.com")
	mustFind(t, r, CodePersonalData, PassNone, "meta-pixel", "SHA-256 hash of the email address jane@example.com")
	// Automatic advanced matching read the address PXTA typed in.
	mustFind(t, r, CodePersonalData, PassNone, "meta-pixel", "/newsletter", ProbeEmail)
	mustFind(t, r, CodeSearchTerm, PassNone, "google-analytics-4", "wool socks")
	mustFind(t, r, CodeSensitivePage, PassNone, "meta-pixel", "checkout")
	if r.Counts[SevHigh] == 0 {
		t.Error("no high findings")
	}
}

// The clinic: Google Analytics waits for consent, TikTok and LinkedIn don't.
func TestBrowserClinic(t *testing.T) {
	needBrowser(t)
	f := startFixtures(t)
	r := auditFixture(t, f, "https://www.cedarvalleyclinic.test/", nil)
	if r.Banner.Platform != "cookiebot" {
		t.Fatalf("banner %+v", r.Banner)
	}
	if fired(r, "google-analytics-4", PassNone) || fired(r, "google-analytics-4", PassReject) {
		t.Error("Google Analytics fired without consent on the clinic")
	}
	if !fired(r, "google-analytics-4", PassAccept) {
		t.Error("Google Analytics did not fire after accept")
	}
	mustFind(t, r, CodeSensitivePage, PassNone, "tiktok-pixel", "/conditions/anxiety", "about health")
	mustFind(t, r, CodeSensitivePage, PassReject, "linkedin-insight", "about health")
	mustFind(t, r, CodeSearchTerm, PassNone, "tiktok-pixel", "anxiety medication")
	mustFind(t, r, CodeTrackerAfterReject, PassReject, "tiktok-pixel")
}

// The bakery: set up correctly, so nothing medium or high.
func TestBrowserBakery(t *testing.T) {
	needBrowser(t)
	f := startFixtures(t)
	r := auditFixture(t, f, "https://www.tidewaterbakery.test/", nil)
	if r.Banner.Platform != "didomi" {
		t.Fatalf("banner %+v", r.Banner)
	}
	if r.Counts[SevHigh]+r.Counts[SevMedium] != 0 {
		dumpFindings(t, r)
		t.Fatal("a correctly set up site got medium or high findings")
	}
	for _, id := range []string{"google-analytics-4", "meta-pixel"} {
		if !fired(r, id, PassAccept) {
			t.Errorf("%s did not fire after accept", id)
		}
	}
	html, _ := RenderHTML(r)
	if !strings.Contains(string(html), "respects the choice") {
		t.Error("report does not say the tags respect the choice")
	}
}

// The loan site: tags load on any answer, and Consent Mode says granted.
func TestBrowserLoans(t *testing.T) {
	needBrowser(t)
	f := startFixtures(t)
	r := auditFixture(t, f, "https://www.marlowhomeloans.test/", nil)
	if r.Banner.Platform != "usercentrics" || !strings.Contains(r.Banner.Actions[PassReject], "API") {
		t.Fatalf("banner %+v (the closed shadow root should force the API)", r.Banner)
	}
	if fired(r, "microsoft-uet", PassNone) {
		t.Error("UET fired before an answer")
	}
	mustFind(t, r, CodeTrackerAfterReject, PassReject, "microsoft-uet")
	mustFind(t, r, CodeTrackerAfterReject, PassReject, "x-pixel")
	mustFind(t, r, CodeConsentModeGranted, PassReject, "google-analytics-4", "G111")
	mustFind(t, r, CodeSensitivePage, PassReject, "microsoft-uet", "money trouble")
	mustFind(t, r, CodeSearchTerm, PassReject, "google-analytics-4", "bankruptcy")
}

// Each consent platform, set up right and set up wrong.
func TestBrowserConsentPlatforms(t *testing.T) {
	needBrowser(t)
	f := startFixtures(t)
	want := map[string]string{"onetrust": "onetrust", "cookiebot": "cookiebot", "didomi": "didomi", "usercentrics": "usercentrics",
		"generic": "generic", "iframe": "generic", "delayed": "onetrust"}
	for _, platform := range []string{"onetrust", "cookiebot", "didomi", "usercentrics", "generic", "iframe", "delayed"} {
		for _, mode := range []string{"good", "bad"} {
			platform, mode := platform, mode
			t.Run(platform+"-"+mode, func(t *testing.T) {
				r := auditFixture(t, f, "https://cmp-"+platform+"-"+mode+".test/", func(o *Options) {
					o.MaxPages = 2
					if platform == "delayed" {
						o.BannerWait = 6 * time.Second
					}
				})
				if !r.Banner.Found || r.Banner.Platform != want[platform] {
					t.Fatalf("banner %+v", r.Banner)
				}
				if platform == "iframe" && r.Banner.Frame != "iframe" {
					t.Errorf("banner frame %q, want iframe", r.Banner.Frame)
				}
				if len(r.Passes) != 3 {
					t.Fatalf("passes %v, problems %v", r.Passes, r.Banner.Problems)
				}
				if !fired(r, "google-analytics-4", PassAccept) {
					t.Error("no Google Analytics after accept")
				}
				if mode == "good" {
					mustNotFind(t, r, CodeTrackerBeforeConsent, "", "google-analytics-4")
					mustNotFind(t, r, CodeTrackerAfterReject, "", "google-analytics-4")
				} else {
					mustFind(t, r, CodeTrackerBeforeConsent, PassNone, "google-analytics-4")
					mustFind(t, r, CodeTrackerAfterReject, PassReject, "google-analytics-4")
				}
			})
		}
	}
}

func TestBrowserConsentModeMismatch(t *testing.T) {
	needBrowser(t)
	f := startFixtures(t)
	r := auditFixture(t, f, "https://www.consentmode.test/", nil)
	if r.Banner.Found {
		t.Fatalf("banner %+v on a site without one", r.Banner)
	}
	f1 := mustFind(t, r, CodeConsentModeMismatch, PassNoBanner, "google-analytics-4", "G100", "user ID")
	if f1.Severity != SevHigh {
		t.Errorf("severity %s", f1.Severity)
	}
}

// Every encoding, sent by a real browser to an unclassified collector.
func TestBrowserEncodings(t *testing.T) {
	needBrowser(t)
	f := startFixtures(t)
	r := auditFixture(t, f, "https://www.encodings.test/", nil)
	got := map[string]bool{}
	for _, fd := range r.Findings {
		if fd.Code != CodePersonalData {
			continue
		}
		for _, l := range fd.Evidence.Highlight {
			got[l.Value] = true
			if strings.Contains(l.What, "hashed@encodings.test") {
				got["hashed@encodings.test"] = true
			}
		}
	}
	for _, kind := range []string{"plain", "urlenc", "double", "base64", "pageaddr", "json", "jsonfield", "lines", "beacon", "hashed"} {
		if !got[kind+"@encodings.test"] {
			dumpFindings(t, r)
			t.Errorf("%s: email not found", kind)
		}
	}
}

// Trackers that load after a timer, on scroll, and from a tag manager.
func TestBrowserLateTrackers(t *testing.T) {
	needBrowser(t)
	f := startFixtures(t)
	r := auditFixture(t, f, "https://www.latetrackers.test/", nil)
	for _, id := range []string{"meta-pixel", "tiktok-pixel", "google-analytics-4"} {
		if !fired(r, id, PassNoBanner) {
			dumpFindings(t, r)
			t.Errorf("%s was not caught", id)
		}
	}
}

// Requests from a cross-site iframe, a worker, and a beacon sent on unload.
func TestBrowserFramesWorkersUnload(t *testing.T) {
	needBrowser(t)
	f := startFixtures(t)
	r := auditFixture(t, f, "https://www.framesworkers.test/", nil)
	var iframe, worker, unload bool
	for _, q := range r.requests {
		switch {
		case strings.Contains(q.URL, "facebook.com/tr") && q.Target == "iframe":
			iframe = true
		case strings.Contains(q.URL, "events.workerstats.test") && strings.Contains(q.Target, "worker"):
			worker = true
		case strings.Contains(q.URL, "beacon.exitmetrics.test") && q.Phase == "unload":
			unload = true
		}
	}
	if !iframe || !worker || !unload {
		for _, q := range r.requests {
			t.Logf("%s %s %s %s", q.Target, q.Phase, q.Type, q.URL)
		}
		t.Fatalf("iframe %v, worker %v, unload %v", iframe, worker, unload)
	}
	if !fired(r, "unclassified:beacon.exitmetrics.test", PassNoBanner) {
		t.Error("unload beacon not listed as an unclassified tracker")
	}
}

func TestBrowserNoTrackers(t *testing.T) {
	needBrowser(t)
	f := startFixtures(t)
	r := auditFixture(t, f, "https://www.notrackers.test/", nil)
	if len(r.Findings) != 0 || len(r.Trackers) != 0 {
		dumpFindings(t, r)
		t.Fatal("findings on a site with no trackers")
	}
	if len(r.Pages) != 2 {
		t.Errorf("visited %d pages, want 2", len(r.Pages))
	}
}

func TestBrowserRobots(t *testing.T) {
	needBrowser(t)
	f := startFixtures(t)
	r := auditFixture(t, f, "https://www.robots.test/", func(o *Options) { o.IgnoreRobots = false })
	for _, p := range r.Pages {
		if strings.Contains(p.URL, "/private") {
			t.Fatalf("visited %s, which robots.txt disallows", p.URL)
		}
	}
	if len(r.Pages) != 2 {
		t.Errorf("visited %d pages, want 2", len(r.Pages))
	}
}

// The browser is killed in the middle of a long crawl; the audit restarts it
// and finishes every page.
func TestBrowserCrashRecovery(t *testing.T) {
	needBrowser(t)
	f := startFixtures(t)
	pages := 40
	if s := os.Getenv("PXTA_CRASH_PAGES"); s != "" {
		pages, _ = strconv.Atoi(s)
	}
	killAt := pages / 3
	var a *Result
	start := time.Now()
	a = auditFixture(t, f, "https://www.bigsite.test/p/0", func(o *Options) {
		o.MaxPages, o.MaxDepth, o.Idle = pages, 20, 300*time.Millisecond
		o.OnPage = func(pass string, page int) {
			if page == killAt {
				killBrowser(t)
			}
		}
	})
	if a.Restarts < 1 {
		t.Fatal("the browser was not restarted")
	}
	seen := map[string]bool{}
	for _, p := range a.Pages {
		if p.Error != "" {
			t.Logf("page %d error: %s", p.Page, p.Error)
		}
		seen[p.URL] = true
	}
	if len(seen) != pages {
		t.Fatalf("visited %d distinct pages, want %d", len(seen), pages)
	}
	hits := 0
	for _, q := range a.requests {
		if strings.Contains(q.URL, "google-analytics.com/g/collect") {
			hits++
		}
	}
	if hits < pages {
		t.Errorf("%d analytics hits recorded for %d pages", hits, pages)
	}
	t.Logf("crash test: %d pages, browser killed at page %d, %d restart(s), %d hits, %s", pages, killAt, a.Restarts, hits, time.Since(start).Round(time.Second))
	if dir := os.Getenv("PXTA_RECORD_DIR"); dir != "" {
		os.WriteFile(filepath.Join(dir, "crash-recovery.txt"), []byte(fmt.Sprintf(
			"pages: %d\nbrowser killed after page: %d\nbrowser restarts: %d\ndistinct pages recorded: %d\nanalytics hits recorded: %d\npages with an error: %d\n",
			pages, killAt+1, a.Restarts, len(seen), hits, countErrors(a.Pages))), 0o644)
	}
}

func countErrors(vs []Visit) int {
	n := 0
	for _, v := range vs {
		if v.Error != "" {
			n++
		}
	}
	return n
}

// killBrowser kills the newest browser this process started, as a crash
// would.
func killBrowser(t *testing.T) {
	t.Helper()
	launchedMu.Lock()
	pid := lastLaunchedPid
	launchedMu.Unlock()
	if pid == 0 {
		t.Fatal("no browser pid")
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Kill(); err != nil {
		t.Logf("kill %d: %v", pid, err)
	}
}

// An interrupted audit resumes where it stopped.
func TestBrowserResume(t *testing.T) {
	needBrowser(t)
	f := startFixtures(t)
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	o := Options{StartURL: "https://www.bigsite.test/p/0", OutDir: dir, MaxPages: 12, MaxDepth: 5, PageWait: 10 * time.Second,
		Idle: 300 * time.Millisecond, Delay: 0, IgnoreRobots: true, BrowserArgs: f.Args(), HTTPClient: f.Client(), Log: testLog{t},
		OnPage: func(pass string, page int) {
			if page == 4 {
				cancel()
			}
		}}
	if _, err := Audit(ctx, o); err == nil {
		t.Fatal("the cancelled audit finished")
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json")); err != nil {
		t.Fatal("no state.json after an interrupted audit")
	}
	o.Resume, o.OnPage = true, nil
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel2()
	r, err := Audit(ctx2, o)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, p := range r.Pages {
		seen[p.URL]++
	}
	if len(seen) != 12 {
		t.Fatalf("%d distinct pages after resume, want 12", len(seen))
	}
	for u, n := range seen {
		if n != 1 {
			t.Errorf("%s recorded %d times", u, n)
		}
	}
	perPage := map[int]int{}
	for _, q := range r.requests {
		if strings.Contains(q.URL, "g/collect") {
			perPage[q.Page]++
		}
	}
	for i := 0; i < 12; i++ {
		if perPage[i] != 1 {
			t.Errorf("page %d has %d analytics hits, want 1", i, perPage[i])
		}
	}
}

// TestGallery writes the sample reports for pxta.com. It runs only when
// PXTA_GALLERY_DIR is set (scripts/record-results.sh sets it), with the
// default timings a user gets.
func TestGallery(t *testing.T) {
	dir := os.Getenv("PXTA_GALLERY_DIR")
	if dir == "" {
		t.Skip("set PXTA_GALLERY_DIR to write the sample reports")
	}
	needBrowser(t)
	f := startFixtures(t)
	for name, start := range map[string]string{
		"harbor-pine-outfitters": "https://www.harborpine.test/",
		"cedar-valley-clinic":    "https://www.cedarvalleyclinic.test/",
		"tidewater-bakery":       "https://www.tidewaterbakery.test/",
		"marlow-home-loans":      "https://www.marlowhomeloans.test/",
	} {
		out := filepath.Join(dir, name)
		os.MkdirAll(out, 0o755)
		auditFixture(t, f, start, func(o *Options) {
			o.OutDir = out
			o.Idle, o.PageWait, o.BannerWait, o.Delay = 2*time.Second, 15*time.Second, 6*time.Second, 0
			o.IgnoreRobots = false
		})
	}
}

// alert(), confirm(), prompt() and a beforeunload prompt must not stop the
// audit.
func TestBrowserDialogs(t *testing.T) {
	needBrowser(t)
	f := startFixtures(t)
	start := time.Now()
	r := auditFixture(t, f, "https://www.dialogs.test/", nil)
	if len(r.Pages) != 2 {
		dumpFindings(t, r)
		t.Fatalf("visited %d pages, want 2", len(r.Pages))
	}
	for _, p := range r.Pages {
		if p.Error != "" {
			t.Errorf("%s: %s", p.URL, p.Error)
		}
	}
	if d := time.Since(start); d > 2*time.Minute {
		t.Errorf("the audit took %s", d)
	}
}

// An "OK" button next to a footer link to the privacy policy is not a
// consent banner.
func TestBrowserNotABanner(t *testing.T) {
	needBrowser(t)
	f := startFixtures(t)
	r := auditFixture(t, f, "https://www.okbutton.test/", nil)
	if r.Banner.Found {
		t.Fatalf("found a %q banner on a page without one (%v)", r.Banner.Platform, r.Banner.Actions)
	}
}

// A start address that redirects to www still crawls the site.
func TestBrowserRedirectedStart(t *testing.T) {
	needBrowser(t)
	f := startFixtures(t)
	r := auditFixture(t, f, "https://redirect.test/", nil)
	if len(r.Pages) != 4 {
		for _, p := range r.Pages {
			t.Log(p.URL, p.FinalURL)
		}
		t.Fatalf("visited %d pages, want 4", len(r.Pages))
	}
}

// --passes reject,accept leaves the unanswered pass out of the report.
func TestBrowserPassesOption(t *testing.T) {
	needBrowser(t)
	f := startFixtures(t)
	r := auditFixture(t, f, "https://cmp-onetrust-bad.test/", func(o *Options) { o.Passes = []string{PassReject, PassAccept} })
	if contains(r.Passes, PassNone) {
		t.Fatalf("passes %v include the unanswered pass", r.Passes)
	}
	for _, fd := range r.Findings {
		if fd.Pass == PassNone {
			t.Errorf("finding from the unanswered pass: %s", fd.Sentence)
		}
	}
	if len(r.Findings) == 0 {
		t.Error("no findings from the reject pass on a site that ignores reject")
	}
}
