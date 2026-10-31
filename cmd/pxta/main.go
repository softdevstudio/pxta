// Command pxta audits the tracking pixels on a website: which ones are on
// which pages, what fires before the consent banner is answered or after it
// is rejected, and what data leaves the browser.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	neturl "net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/softdevstudio/pxta"
)

const usage = `pxta: Pixel Tracking Audit

Usage:
  pxta audit <url> [options]   crawl a site and write an evidence report
  pxta check <url> [options]   audit a site and fail (exit 1) when it breaks the rules
  pxta check --findings FILE   judge an earlier audit's findings.json
  pxta catalog                 list the trackers PXTA recognises
  pxta version                 print the version

Run "pxta audit -h" or "pxta check -h" for the options.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "pxta %s\n", pxta.Version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "catalog":
		return runCatalog(args[1:], stdout, stderr)
	case "audit":
		return runAudit(args[1:], stdout, stderr)
	case "check":
		return runCheck(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "pxta: unknown command %q\n\n%s", args[0], usage)
	return 2
}

func runCatalog(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("catalog", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("catalog", "", "folder of extra catalog files (*.json)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cat, err := pxta.LoadCatalog(*dir)
	if err != nil {
		fmt.Fprintln(stderr, "pxta:", err)
		return 2
	}
	fmt.Fprintf(stdout, "Tracker catalog %s, %d trackers\n\n", pxta.CatalogVersion, len(cat.Trackers))
	for _, t := range cat.Trackers {
		var hosts []string
		for _, e := range t.Endpoints {
			hosts = append(hosts, e.Host+e.Path)
		}
		if len(hosts) == 0 {
			for _, s := range t.Scripts {
				hosts = append(hosts, s.Host+s.Path+" (script)")
			}
		}
		fmt.Fprintf(stdout, "%-22s %-32s %s\n", t.ID, t.Name, strings.Join(hosts, ", "))
	}
	return 0
}

// auditFlags are the options audit and check share.
type auditFlags struct {
	out, sitemap, browser, passes, catDir       *string
	pages, depth                                *int
	wait, idle, bannerWait, delay               *time.Duration
	ignoreRobots, noFill, resume, quiet, redact *bool
	emails                                      listFlag
}

func addAuditFlags(fs *flag.FlagSet) *auditFlags {
	f := &auditFlags{}
	f.out = fs.String("out", "pxta-report", "folder for report.html, findings.json and requests.har")
	f.pages = fs.Int("pages", 20, "most pages to visit")
	f.depth = fs.Int("depth", 3, "how many links deep to follow from the start page")
	f.sitemap = fs.String("sitemap", "", "sitemap address to add pages from")
	f.browser = fs.String("browser", "", "path to Chrome, Chromium or Edge (default: found automatically, or $PXTA_BROWSER)")
	f.wait = fs.Duration("wait", 15*time.Second, "longest time to spend on one page")
	f.idle = fs.Duration("idle", 2*time.Second, "a page is finished after this long without a new request")
	f.bannerWait = fs.Duration("banner-wait", 6*time.Second, "how long to look for a consent banner")
	f.delay = fs.Duration("delay", time.Second, "pause between page loads")
	f.ignoreRobots = fs.Bool("ignore-robots", false, "visit pages that robots.txt disallows (your own site only)")
	f.noFill = fs.Bool("no-fill", false, "don't type the marker address into email fields")
	f.passes = fs.String("passes", "none,reject,accept", "consent passes to run")
	f.resume = fs.Bool("resume", false, "continue an audit that was interrupted, from the --out folder")
	f.catDir = fs.String("catalog", "", "folder of extra catalog files (*.json)")
	f.quiet = fs.Bool("quiet", false, "print only the summary")
	f.redact = fs.Bool("redact", false, "replace personal values in the report with REDACTED, for reports that get shared")
	fs.Var(&f.emails, "email", "an email address whose hashes to look for (repeatable)")
	return f
}

// splitURL lets the URL come before or after the options.
func splitURL(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

// audit runs an audit from the shared flags. code is the exit code to use
// when err is set.
func (f *auditFlags) audit(url string, stderr io.Writer) (res *pxta.Result, code int, err error) {
	if !strings.Contains(url, "://") {
		url = "https://" + url
	}
	if u, perr := neturl.Parse(url); perr != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, 2, fmt.Errorf("%s: give an http(s) address", url)
	}
	cat, err := pxta.LoadCatalog(*f.catDir)
	if err != nil {
		return nil, 2, err
	}
	var ps []string
	for _, p := range strings.Split(*f.passes, ",") {
		p = strings.TrimSpace(p)
		switch p {
		case "none", "reject", "accept":
			ps = append(ps, p)
		case "":
		default:
			return nil, 2, fmt.Errorf("unknown pass %q (use none, reject, accept)", p)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	log := stderr
	if *f.quiet {
		log = io.Discard
	}
	res, err = pxta.Audit(ctx, pxta.Options{
		StartURL: url, MaxPages: *f.pages, MaxDepth: *f.depth, Sitemap: *f.sitemap, PageWait: *f.wait, Idle: *f.idle,
		BannerWait: *f.bannerWait, Delay: *f.delay, IgnoreRobots: *f.ignoreRobots, FillForms: !*f.noFill, KnownEmails: f.emails,
		Passes: ps, OutDir: *f.out, Resume: *f.resume, BrowserPath: *f.browser, Catalog: cat, Log: log,
		ReproBase: "pxta audit", Redact: *f.redact,
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil, 130, fmt.Errorf("stopped. Run the same command with --resume to carry on from %s", *f.out)
		}
		return nil, 3, err
	}
	return res, 0, nil
}

func runAudit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, "Usage: pxta audit <url> [options]\n\nOptions:\n")
		fs.PrintDefaults()
	}
	af := addAuditFlags(fs)
	url, rest := splitURL(args)
	if err := fs.Parse(rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if url == "" && fs.NArg() > 0 {
		url = fs.Arg(0)
	}
	if url == "" {
		fs.Usage()
		return 2
	}
	res, code, err := af.audit(url, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "pxta:", err)
		if code == 3 {
			code = 2 // audit has always exited 2 on a failed run
		}
		return code
	}
	printSummary(stdout, res, *af.out)
	return 0
}

const checkUsage = `Usage:
  pxta check <url> [options]         audit the site, then judge the audit
  pxta check --findings FILE [opts]  judge an earlier audit's findings.json

Exit codes: 0 the rules hold, 1 a rule is broken, 2 a usage or rules-file
error, 3 the audit could not run, 130 stopped.

Options:
`

func runCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, checkUsage)
		fs.PrintDefaults()
	}
	af := addAuditFlags(fs)
	rulesFile := fs.String("rules", "", "rules file (JSON); default: fail on medium and above, and on a banner PXTA could not answer")
	findings := fs.String("findings", "", "judge this findings.json instead of running an audit")
	format := fs.String("format", "text", "how to print problems: text, or github for workflow annotations")
	summary := fs.String("summary", "", "append a Markdown summary to this file (for $GITHUB_STEP_SUMMARY)")
	url, rest := splitURL(args)
	if err := fs.Parse(rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if url == "" && fs.NArg() > 0 {
		url = fs.Arg(0)
	}
	if fs.NArg() > 1 || (url != "" && *findings != "") || (url == "" && *findings == "") {
		fs.Usage()
		return 2
	}
	if *format != "text" && *format != "github" {
		fmt.Fprintf(stderr, "pxta: unknown format %q (use text or github)\n", *format)
		return 2
	}
	rules := pxta.DefaultRules()
	if *rulesFile != "" {
		r, err := pxta.LoadRules(*rulesFile)
		if err != nil {
			fmt.Fprintln(stderr, "pxta:", err)
			return 2
		}
		cat, err := pxta.LoadCatalog(*af.catDir)
		if err != nil {
			fmt.Fprintln(stderr, "pxta:", err)
			return 2
		}
		if err := r.CheckTrackers(cat); err != nil {
			fmt.Fprintf(stderr, "pxta: %s: %v\n", *rulesFile, err)
			return 2
		}
		rules = r
	}
	var res *pxta.Result
	outDir := ""
	if *findings != "" {
		r, err := pxta.ReadResult(*findings)
		if err != nil {
			fmt.Fprintln(stderr, "pxta:", err)
			return 2
		}
		if *af.redact && !r.Redacted {
			fmt.Fprintln(stderr, "pxta: --redact works while auditing; this findings.json was written without it")
			return 2
		}
		res = r
	} else {
		r, code, err := af.audit(url, stderr)
		if err != nil {
			fmt.Fprintln(stderr, "pxta:", err)
			return code
		}
		res, outDir = r, *af.out
		printSummary(stderr, res, outDir)
	}
	c := pxta.Check(res, rules)
	if outDir != "" {
		j, _ := json.MarshalIndent(c, "", "  ")
		if err := os.WriteFile(filepath.Join(outDir, "check.json"), append(j, '\n'), 0o644); err != nil {
			fmt.Fprintln(stderr, "pxta:", err)
			return 3
		}
		if err := res.VerifyRedacted(outDir); err != nil {
			os.Remove(filepath.Join(outDir, "check.json"))
			fmt.Fprintln(stderr, "pxta:", err)
			return 3
		}
	}
	if *format == "github" {
		c.WriteGitHub(stdout)
	}
	c.WriteText(stdout)
	if *summary != "" {
		f, err := os.OpenFile(*summary, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			_, err = io.WriteString(f, c.Markdown()+"\n")
			if cerr := f.Close(); err == nil {
				err = cerr
			}
		}
		if err != nil {
			// The verdict stands; a summary that couldn't be written is only a warning.
			fmt.Fprintln(stderr, "pxta: warning: summary not written:", err)
		}
	}
	if !c.Pass {
		return 1
	}
	return 0
}

func printSummary(w io.Writer, r *pxta.Result, out string) {
	fmt.Fprintf(w, "\n%s: %d high, %d medium, %d low, %d for information\n", r.Site,
		r.Counts[pxta.SevHigh], r.Counts[pxta.SevMedium], r.Counts[pxta.SevLow], r.Counts[pxta.SevInfo])
	switch {
	case !r.Banner.Found:
		fmt.Fprintln(w, "No consent banner found.")
	default:
		fmt.Fprintf(w, "Consent banner from %s\n", pxta.PlatformName(r.Banner.Platform))
	}
	shown := 0
	for _, f := range r.Findings {
		if f.Severity == pxta.SevInfo || shown >= 8 {
			continue
		}
		fmt.Fprintf(w, "  %-6s %s\n", strings.ToUpper(f.Severity), f.Sentence)
		shown++
	}
	more := 0
	for _, f := range r.Findings {
		if f.Severity != pxta.SevInfo {
			more++
		}
	}
	if more > shown {
		fmt.Fprintf(w, "  ... and %d more\n", more-shown)
	}
	names := make([]string, 0, len(r.Trackers))
	for _, t := range r.Trackers {
		names = append(names, t.Name)
	}
	sort.Strings(names)
	if len(names) > 0 {
		fmt.Fprintf(w, "Trackers: %s\n", strings.Join(names, ", "))
	}
	abs, _ := filepath.Abs(filepath.Join(out, "report.html"))
	fmt.Fprintf(w, "Report: %s\n", abs)
}
