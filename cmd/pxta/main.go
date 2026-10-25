// Command pxta audits the tracking pixels on a website: which ones are on
// which pages, what fires before the consent banner is answered or after it
// is rejected, and what data leaves the browser.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
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
  pxta catalog                 list the trackers PXTA recognises
  pxta version                 print the version

Run "pxta audit -h" for the audit options.
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

func runAudit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, "Usage: pxta audit <url> [options]\n\nOptions:\n")
		fs.PrintDefaults()
	}
	out := fs.String("out", "pxta-report", "folder for report.html, findings.json and requests.har")
	pages := fs.Int("pages", 20, "most pages to visit")
	depth := fs.Int("depth", 3, "how many links deep to follow from the start page")
	sitemap := fs.String("sitemap", "", "sitemap address to add pages from")
	browser := fs.String("browser", "", "path to Chrome, Chromium or Edge (default: found automatically, or $PXTA_BROWSER)")
	wait := fs.Duration("wait", 15*time.Second, "longest time to spend on one page")
	idle := fs.Duration("idle", 2*time.Second, "a page is finished after this long without a new request")
	bannerWait := fs.Duration("banner-wait", 6*time.Second, "how long to look for a consent banner")
	delay := fs.Duration("delay", time.Second, "pause between page loads")
	ignoreRobots := fs.Bool("ignore-robots", false, "visit pages that robots.txt disallows (your own site only)")
	noFill := fs.Bool("no-fill", false, "don't type the marker address into email fields")
	passes := fs.String("passes", "none,reject,accept", "consent passes to run")
	resume := fs.Bool("resume", false, "continue an audit that was interrupted, from the --out folder")
	catDir := fs.String("catalog", "", "folder of extra catalog files (*.json)")
	quiet := fs.Bool("quiet", false, "print only the summary")
	var emails listFlag
	fs.Var(&emails, "email", "an email address whose hashes to look for (repeatable)")
	// Allow the URL before or after the options.
	var url string
	rest := args
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		url, rest = rest[0], rest[1:]
	}
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
	if !strings.Contains(url, "://") {
		url = "https://" + url
	}
	cat, err := pxta.LoadCatalog(*catDir)
	if err != nil {
		fmt.Fprintln(stderr, "pxta:", err)
		return 2
	}
	var ps []string
	for _, p := range strings.Split(*passes, ",") {
		p = strings.TrimSpace(p)
		switch p {
		case "none", "reject", "accept":
			ps = append(ps, p)
		case "":
		default:
			fmt.Fprintf(stderr, "pxta: unknown pass %q (use none, reject, accept)\n", p)
			return 2
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	log := stderr
	if *quiet {
		log = io.Discard
	}
	res, err := pxta.Audit(ctx, pxta.Options{
		StartURL: url, MaxPages: *pages, MaxDepth: *depth, Sitemap: *sitemap, PageWait: *wait, Idle: *idle,
		BannerWait: *bannerWait, Delay: *delay, IgnoreRobots: *ignoreRobots, FillForms: !*noFill, KnownEmails: emails,
		Passes: ps, OutDir: *out, Resume: *resume, BrowserPath: *browser, Catalog: cat, Log: log,
		ReproBase: "pxta audit",
	})
	if err != nil {
		if ctx.Err() != nil {
			fmt.Fprintf(stderr, "pxta: stopped. Run the same command with --resume to carry on from %s.\n", *out)
			return 130
		}
		fmt.Fprintln(stderr, "pxta:", err)
		return 2
	}
	printSummary(stdout, res, *out)
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
