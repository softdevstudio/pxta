package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/softdevstudio/pxta"
)

const diffUsage = `Usage:
  pxta diff OLD/findings.json NEW/findings.json [options]

Lists what changed between two audits: new and gone findings, trackers
that start or stop sending data in a pass, and banner changes. Pages are
compared by path, so a staging audit can be compared with production.

Exit codes: 0 no change, 1 changes (or, with --fail-on, a new finding at
that severity or above, a lost pass, an audit that visited nothing, or a
banner that's gone or no longer answered), 2 a usage error or a redacted
audit against an unredacted one, 3 a file could not be read or written.

Options:
`

func runDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, diffUsage)
		fs.PrintDefaults()
	}
	failOn := fs.String("fail-on", "", "exit 1 only for a new finding at this severity or above: high, medium, low, info, or never (default: any change)")
	format := fs.String("format", "text", "text, json, or github for workflow annotations")
	summary := fs.String("summary", "", "append a Markdown summary to this file (for $GITHUB_STEP_SUMMARY)")
	out := fs.String("out", "", "also write the diff as JSON to this file")
	newPages := fs.Bool("new-pages", false, "count findings on pages the old audit never reached as new (default: not compared)")
	// Options may come before, between or after the two files.
	var files []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		files = append(files, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(files) != 2 {
		fs.Usage()
		return 2
	}
	switch *failOn {
	case "", "never", pxta.SevHigh, pxta.SevMedium, pxta.SevLow, pxta.SevInfo:
	default:
		fmt.Fprintf(stderr, "pxta: unknown --fail-on %q (use high, medium, low, info or never)\n", *failOn)
		return 2
	}
	switch *format {
	case "text", "json", "github":
	default:
		fmt.Fprintf(stderr, "pxta: unknown format %q (use text, json or github)\n", *format)
		return 2
	}
	var res [2]*pxta.Result
	for i, f := range files {
		r, err := pxta.ReadResult(f)
		if err != nil {
			fmt.Fprintln(stderr, "pxta:", err)
			return 3
		}
		res[i] = r
	}
	d, err := pxta.Diff(res[0], res[1], pxta.DiffOptions{FailOn: *failOn, NewPages: *newPages})
	if err != nil {
		fmt.Fprintln(stderr, "pxta:", err)
		return 2
	}
	j, _ := json.MarshalIndent(d, "", "  ")
	j = append(j, '\n')
	if *out != "" {
		if err := os.WriteFile(*out, j, 0o644); err != nil {
			fmt.Fprintln(stderr, "pxta:", err)
			return 3
		}
	}
	switch *format {
	case "json":
		stdout.Write(j)
	case "github":
		d.WriteGitHub(stdout)
		d.WriteText(stdout, true)
	default:
		d.WriteText(stdout, false)
	}
	if *summary != "" {
		f, err := os.OpenFile(*summary, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			_, err = io.WriteString(f, d.Markdown()+"\n")
			if cerr := f.Close(); err == nil {
				err = cerr
			}
		}
		if err != nil {
			fmt.Fprintln(stderr, "pxta: warning: summary not written:", err)
		}
	}
	if d.Fail {
		return 1
	}
	return 0
}
