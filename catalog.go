package pxta

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// CatalogVersion changes whenever a catalog entry is added or changed.
const CatalogVersion = "2026.10.25"

//go:embed catalog/*.json
var catalogFS embed.FS

// Pattern matches a request by host and path. A host matches itself and its
// subdomains. The path matches segment by segment, "*" standing for any one
// segment; the request's path may continue past the pattern.
type Pattern struct {
	Host string `json:"host"`
	Path string `json:"path"`
}

// ParamInfo says what a parameter means and what kind of data it carries.
type ParamInfo struct {
	Meaning string `json:"meaning"`
	Kind    string `json:"kind"`
}

// Parameter kinds used by the rules.
const (
	KindAccount   = "account"
	KindEvent     = "event"
	KindPageURL   = "page_url"
	KindReferrer  = "referrer"
	KindTitle     = "title"
	KindClientID  = "client_id"
	KindUserID    = "user_id"
	KindEmailHash = "email_hash"
	KindPhoneHash = "phone_hash"
	KindNameHash  = "name_hash"
	KindUserHash  = "user_hash"
	KindConsent   = "consent"
	KindCustom    = "custom"
	KindOther     = "other"
)

var validKinds = map[string]bool{KindAccount: true, KindEvent: true, KindPageURL: true, KindReferrer: true, KindTitle: true,
	KindClientID: true, KindUserID: true, KindEmailHash: true, KindPhoneHash: true, KindNameHash: true, KindUserHash: true,
	KindConsent: true, KindCustom: true, KindOther: true}

// Tracker is one catalog entry.
type Tracker struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	Vendor      string               `json:"vendor"`
	Scripts     []Pattern            `json:"scripts"`
	Endpoints   []Pattern            `json:"endpoints"`
	ConsentMode bool                 `json:"consent_mode"`
	Params      map[string]ParamInfo `json:"params"`
	Prefixes    map[string]ParamInfo `json:"prefixes"`
	Sample      *Sample              `json:"sample"`
}

// Sample is a recorded request each catalog entry ships with; the tests
// decode every sample.
type Sample struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Body   string `json:"body"`
	Script bool   `json:"script"`
}

// Catalog is the set of known trackers.
type Catalog struct {
	Trackers []*Tracker
}

// LoadCatalog reads the built-in catalog, plus every *.json file in extraDir
// when it is set. An extra entry with the same ID replaces the built-in one.
func LoadCatalog(extraDir string) (*Catalog, error) {
	byID := map[string]*Tracker{}
	err := fs.WalkDir(catalogFS, "catalog", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") {
			return err
		}
		b, err := catalogFS.ReadFile(p)
		if err != nil {
			return err
		}
		t, err := parseTracker(b, p)
		if err != nil {
			return err
		}
		byID[t.ID] = t
		return nil
	})
	if err != nil {
		return nil, err
	}
	if extraDir != "" {
		files, err := filepath.Glob(filepath.Join(extraDir, "*.json"))
		if err != nil {
			return nil, err
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("no *.json catalog files in %s", extraDir)
		}
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				return nil, err
			}
			t, err := parseTracker(b, f)
			if err != nil {
				return nil, err
			}
			byID[t.ID] = t
		}
	}
	c := &Catalog{}
	for _, t := range byID {
		c.Trackers = append(c.Trackers, t)
	}
	sort.Slice(c.Trackers, func(i, j int) bool { return c.Trackers[i].ID < c.Trackers[j].ID })
	return c, nil
}

func parseTracker(b []byte, name string) (*Tracker, error) {
	var t Tracker
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if t.ID == "" || t.Name == "" || t.Vendor == "" {
		return nil, fmt.Errorf("%s: id, name and vendor are required", name)
	}
	if len(t.Scripts)+len(t.Endpoints) == 0 {
		return nil, fmt.Errorf("%s: needs at least one script or endpoint pattern", name)
	}
	for _, p := range append(append([]Pattern{}, t.Scripts...), t.Endpoints...) {
		if p.Host == "" || !strings.HasPrefix(p.Path, "/") {
			return nil, fmt.Errorf("%s: pattern needs a host and a path starting with /", name)
		}
	}
	for k, v := range t.Params {
		if !validKinds[v.Kind] {
			return nil, fmt.Errorf("%s: parameter %s has unknown kind %q", name, k, v.Kind)
		}
	}
	for k, v := range t.Prefixes {
		if !validKinds[v.Kind] {
			return nil, fmt.Errorf("%s: prefix %s has unknown kind %q", name, k, v.Kind)
		}
	}
	return &t, nil
}

func hostMatches(host, pattern string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	pattern = strings.ToLower(pattern)
	return host == pattern || strings.HasSuffix(host, "."+pattern)
}

func pathMatches(p, pattern string) bool {
	ps := strings.Split(p, "/")
	qs := strings.Split(pattern, "/")
	// A pattern ending in "/" is a prefix: the request may go deeper.
	prefix := strings.HasSuffix(pattern, "/")
	if prefix {
		qs = qs[:len(qs)-1]
	}
	if len(ps) < len(qs) {
		return false
	}
	for i, q := range qs {
		if q != "*" && ps[i] != q {
			return false
		}
	}
	// Otherwise whole segments must match ("/tr" is not "/translate"), and
	// the request may still go deeper ("/tr/").
	return true
}

// Match classifies a URL. It returns the tracker and whether the request is a
// collection (data-sending) request rather than a script load.
func (c *Catalog) Match(rawURL string) (t *Tracker, collect bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, false
	}
	host, p := u.Hostname(), u.EscapedPath()
	if p == "" {
		p = "/"
	}
	p = path.Clean(p) + map[bool]string{true: "/", false: ""}[strings.HasSuffix(p, "/") && p != "/"]
	for _, tr := range c.Trackers {
		for _, e := range tr.Endpoints {
			if hostMatches(host, e.Host) && pathMatches(p, e.Path) {
				return tr, true
			}
		}
	}
	for _, tr := range c.Trackers {
		for _, s := range tr.Scripts {
			if hostMatches(host, s.Host) && pathMatches(p, s.Path) {
				return tr, false
			}
		}
	}
	return nil, false
}

// Info describes a decoded parameter key for this tracker.
func (t *Tracker) Info(key string) (ParamInfo, bool) {
	if t == nil {
		return ParamInfo{}, false
	}
	base := baseKey(key)
	if pi, ok := t.Params[base]; ok {
		return pi, true
	}
	best := ""
	for p := range t.Prefixes {
		if strings.HasPrefix(base, p) && len(p) > len(best) {
			best = p
		}
	}
	if best != "" {
		return t.Prefixes[best], true
	}
	return ParamInfo{}, false
}

// baseKey returns the catalog key for a decoded parameter: the line prefix
// of a multi-line body is dropped ("body.2>en" is "en"), and values the
// decoder unpacked from another value ("dl>email", "x#base64") have none.
func baseKey(key string) string {
	for strings.HasPrefix(key, "body.") {
		i := strings.Index(key, ">")
		if i < 0 {
			break
		}
		key = key[i+1:]
	}
	if strings.ContainsAny(key, ">#") {
		return ""
	}
	return key
}

// parentKey is the key a derived value was unpacked from ("dl" for
// "dl>email"), or "" when the value is not derived.
func parentKey(key string) string {
	for strings.HasPrefix(key, "body.") {
		i := strings.Index(key, ">")
		if i < 0 {
			break
		}
		key = key[i+1:]
	}
	if i := strings.IndexAny(key, ">#"); i >= 0 {
		return key[:i]
	}
	return ""
}
