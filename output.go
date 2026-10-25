package pxta

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

//go:embed report.html.tmpl
var reportTemplate string

// WriteOutputs writes requests.har, findings.json and report.html.
func WriteOutputs(r *Result, dir string) error {
	har, err := buildHAR(r)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "requests.har"), har, 0o644); err != nil {
		return err
	}
	sum := sha256.Sum256(har)
	r.HARSHA256 = hex.EncodeToString(sum[:])
	j, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "findings.json"), append(j, '\n'), 0o644); err != nil {
		return err
	}
	html, err := RenderHTML(r)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "report.html"), html, 0o644)
}

// HAR 1.2, request side only: PXTA records what pages send, not what
// trackers answer, so responses are left empty.
type harLog struct {
	Log struct {
		Version string     `json:"version"`
		Creator harCreator `json:"creator"`
		Pages   []harPage  `json:"pages"`
		Entries []harEntry `json:"entries"`
	} `json:"log"`
}
type harCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type harPage struct {
	StartedDateTime string         `json:"startedDateTime"`
	ID              string         `json:"id"`
	Title           string         `json:"title"`
	PageTimings     map[string]int `json:"pageTimings"`
	Comment         string         `json:"comment,omitempty"`
}
type harNV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type harEntry struct {
	Pageref         string         `json:"pageref"`
	StartedDateTime string         `json:"startedDateTime"`
	Time            int            `json:"time"`
	Request         harRequest     `json:"request"`
	Response        harResponse    `json:"response"`
	Cache           struct{}       `json:"cache"`
	Timings         map[string]int `json:"timings"`
	Comment         string         `json:"comment,omitempty"`
}
type harRequest struct {
	Method      string   `json:"method"`
	URL         string   `json:"url"`
	HTTPVersion string   `json:"httpVersion"`
	Cookies     []harNV  `json:"cookies"`
	Headers     []harNV  `json:"headers"`
	QueryString []harNV  `json:"queryString"`
	PostData    *harPost `json:"postData,omitempty"`
	HeadersSize int      `json:"headersSize"`
	BodySize    int      `json:"bodySize"`
}
type harPost struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}
type harResponse struct {
	Status      int     `json:"status"`
	StatusText  string  `json:"statusText"`
	HTTPVersion string  `json:"httpVersion"`
	Cookies     []harNV `json:"cookies"`
	Headers     []harNV `json:"headers"`
	Content     struct {
		Size     int    `json:"size"`
		MimeType string `json:"mimeType"`
	} `json:"content"`
	RedirectURL string `json:"redirectURL"`
	HeadersSize int    `json:"headersSize"`
	BodySize    int    `json:"bodySize"`
}

func buildHAR(r *Result) ([]byte, error) {
	var h harLog
	h.Log.Version = "1.2"
	h.Log.Creator = harCreator{Name: "pxta", Version: Version}
	h.Log.Pages = []harPage{}
	h.Log.Entries = []harEntry{}
	for _, v := range r.Pages {
		h.Log.Pages = append(h.Log.Pages, harPage{StartedDateTime: v.Started.Format("2006-01-02T15:04:05.000Z"), ID: fmt.Sprintf("%s-%d", v.Pass, v.Page),
			Title: v.URL, PageTimings: map[string]int{}, Comment: "pass: " + v.Pass})
	}
	for _, q := range r.requests {
		e := harEntry{Pageref: fmt.Sprintf("%s-%d", q.Pass, q.Page), StartedDateTime: q.Time.Format("2006-01-02T15:04:05.000Z"),
			Timings: map[string]int{"send": 0, "wait": 0, "receive": 0}, Comment: fmt.Sprintf("pass: %s; phase: %s; from: %s; type: %s", q.Pass, q.Phase, q.Target, q.Type)}
		e.Request = harRequest{Method: q.Method, URL: q.URL, HTTPVersion: "HTTP/1.1", Cookies: []harNV{}, Headers: []harNV{},
			QueryString: []harNV{}, HeadersSize: -1, BodySize: len(q.Body)}
		keys := make([]string, 0, len(q.Headers))
		for k := range q.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			e.Request.Headers = append(e.Request.Headers, harNV{k, q.Headers[k]})
		}
		if u, err := url.Parse(q.URL); err == nil {
			for _, kv := range strings.Split(u.RawQuery, "&") {
				if kv == "" {
					continue
				}
				k, v, _ := strings.Cut(kv, "=")
				dk, _ := url.QueryUnescape(k)
				dv, err := url.QueryUnescape(v)
				if err != nil {
					dv = v
				}
				e.Request.QueryString = append(e.Request.QueryString, harNV{dk, dv})
			}
		}
		if q.Body != "" {
			e.Request.PostData = &harPost{MimeType: q.ContentType, Text: q.Body}
		}
		e.Response = harResponse{HTTPVersion: "HTTP/1.1", Cookies: []harNV{}, Headers: []harNV{}, HeadersSize: -1, BodySize: -1}
		h.Log.Entries = append(h.Log.Entries, e)
	}
	return json.MarshalIndent(h, "", " ")
}

var passTitle = map[string]string{PassNone: "Banner not answered", PassReject: "After reject", PassAccept: "After accept", PassNoBanner: "No banner"}

type reportView struct {
	*Result
	Host      string
	High      []*Finding
	Other     []*Finding
	Inventory []*Finding
	PassNames []string
	PassTitle map[string]string
	Rows      []inventoryRow
	Behaviour []behaviourRow
	PageCount int
	Errors    []Visit
}

type inventoryRow struct {
	Name   string
	Vendor string
	Cells  []string
}

type behaviourRow struct {
	Incomplete                                            bool
	Name, BeforeAnswer, AfterReject, AfterAccept, Verdict string
	Bad                                                   bool
}

// RenderHTML builds the self-contained report: no scripts, fonts or images
// from anywhere else, so it can be emailed or filed as it is.
func RenderHTML(r *Result) ([]byte, error) {
	v := reportView{Result: r, PassTitle: passTitle}
	if u, err := url.Parse(r.Site); err == nil {
		v.Host = u.Host
	}
	v.PassNames = r.Passes
	for _, f := range r.Findings {
		switch {
		case f.Code == CodeTrackerPresent:
			v.Inventory = append(v.Inventory, f)
		case f.Severity == SevHigh:
			v.High = append(v.High, f)
		default:
			v.Other = append(v.Other, f)
		}
	}
	pages := map[int]bool{}
	for _, p := range r.Pages {
		pages[p.Page] = true
		if p.Error != "" {
			v.Errors = append(v.Errors, p)
		}
	}
	v.PageCount = len(pages)
	for _, t := range r.Trackers {
		row := inventoryRow{Name: t.Name, Vendor: t.Vendor}
		for _, p := range r.Passes {
			switch {
			case len(t.Fired[p]) > 0:
				row.Cells = append(row.Cells, fmt.Sprintf("sent data on %d page%s", len(t.Fired[p]), plural(len(t.Fired[p]))))
			case len(t.Loaded[p]) > 0:
				row.Cells = append(row.Cells, fmt.Sprintf("loaded on %d page%s", len(t.Loaded[p]), plural(len(t.Loaded[p]))))
			default:
				row.Cells = append(row.Cells, "not seen")
			}
		}
		v.Rows = append(v.Rows, row)
		if r.Banner.Found {
			yn := func(p string) string {
				if !contains(r.Passes, p) {
					return "not tested"
				}
				if len(t.Fired[p]) > 0 {
					return "sends data"
				}
				return "quiet"
			}
			b := behaviourRow{Name: t.Name, BeforeAnswer: yn(PassNone), AfterReject: yn(PassReject), AfterAccept: yn(PassAccept)}
			switch {
			case b.AfterReject == "sends data":
				b.Verdict, b.Bad = "ignores reject", true
			case b.BeforeAnswer == "sends data":
				b.Verdict, b.Bad = "fires before an answer", true
			case b.AfterReject == "quiet" && b.AfterAccept == "sends data":
				b.Verdict = "respects the choice"
			case b.BeforeAnswer != "sends data" && b.AfterReject != "sends data" && b.AfterAccept != "sends data" &&
				(b.BeforeAnswer == "not tested" || b.AfterReject == "not tested" || b.AfterAccept == "not tested"):
				b.Verdict, b.Incomplete = "no data sent in the passes tested", true
			case b.BeforeAnswer == "not tested" || b.AfterReject == "not tested" || b.AfterAccept == "not tested":
				b.Verdict, b.Incomplete = "incomplete: a pass was not tested", true
			default:
				b.Verdict = "no data sent"
			}
			v.Behaviour = append(v.Behaviour, b)
		}
	}
	funcs := template.FuncMap{
		"sevClass": func(s string) string { return "sev-" + s },
		"upper":    strings.ToUpper,
		"leakSet": func(ls []Leak) map[string]bool {
			m := map[string]bool{}
			for _, l := range ls {
				m[l.Key] = true
			}
			return m
		},
		"short": func(s string, n int) string {
			if len([]rune(s)) <= n {
				return s
			}
			return string([]rune(s)[:n]) + "…"
		},
		"count":    func(m map[string]int, k string) int { return m[k] },
		"platform": PlatformName,
	}
	tm, err := template.New("report").Funcs(funcs).Parse(reportTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := tm.Execute(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
