package pxta

import (
	"bufio"
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
)

var skipExt = map[string]bool{".pdf": true, ".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true, ".svg": true,
	".zip": true, ".gz": true, ".tar": true, ".mp4": true, ".mp3": true, ".mov": true, ".avi": true, ".doc": true, ".docx": true,
	".xls": true, ".xlsx": true, ".ppt": true, ".pptx": true, ".exe": true, ".dmg": true, ".msi": true, ".csv": true, ".xml": true,
	".json": true, ".txt": true, ".ics": true, ".woff": true, ".woff2": true, ".css": true, ".js": true}

// normalizeLink keeps same-origin http(s) pages and drops fragments, files
// and links that would sign the visitor out.
func normalizeLink(raw string, origin *url.URL) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", false
	}
	if !strings.EqualFold(u.Host, origin.Host) || u.Scheme != origin.Scheme {
		return "", false
	}
	u.Fragment = ""
	u.RawFragment = ""
	if skipExt[strings.ToLower(path.Ext(u.Path))] {
		return "", false
	}
	lp := strings.ToLower(u.Path)
	for _, w := range []string{"logout", "log-out", "signout", "sign-out", "/cart/add", "add-to-cart", "delete", "unsubscribe"} {
		if strings.Contains(lp, w) {
			return "", false
		}
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), true
}

// Robots holds the rules of a robots.txt that apply to PXTA.
type Robots struct {
	disallow []string
	allow    []string
}

// ParseRobots reads the groups for "pxta" and, failing that, "*".
func ParseRobots(r io.Reader) *Robots {
	type group struct {
		agents         []string
		allow, disallo []string
	}
	var groups []*group
	var cur *group
	lastWasAgent := false
	sc := bufio.NewScanner(io.LimitReader(r, 512<<10))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch k {
		case "user-agent":
			if cur == nil || !lastWasAgent {
				cur = &group{}
				groups = append(groups, cur)
			}
			cur.agents = append(cur.agents, strings.ToLower(v))
			lastWasAgent = true
		case "allow", "disallow":
			lastWasAgent = false
			if cur == nil || v == "" {
				continue
			}
			if k == "allow" {
				cur.allow = append(cur.allow, v)
			} else {
				cur.disallo = append(cur.disallo, v)
			}
		default:
			lastWasAgent = false
		}
	}
	pick := func(name string) *group {
		for _, g := range groups {
			for _, a := range g.agents {
				if a == name {
					return g
				}
			}
		}
		return nil
	}
	g := pick("pxta")
	if g == nil {
		g = pick("*")
	}
	if g == nil {
		return &Robots{}
	}
	return &Robots{disallow: g.disallo, allow: g.allow}
}

// robotsMatch matches a robots.txt path rule, where "*" is any run of
// characters and a final "$" anchors the end.
func robotsMatch(rule, p string) bool {
	anchored := strings.HasSuffix(rule, "$")
	rule = strings.TrimSuffix(rule, "$")
	var sb strings.Builder
	sb.WriteString("^")
	for i, part := range strings.Split(rule, "*") {
		if i > 0 {
			sb.WriteString(".*")
		}
		sb.WriteString(regexp.QuoteMeta(part))
	}
	if anchored {
		sb.WriteString("$")
	}
	re, err := regexp.Compile(sb.String())
	return err == nil && re.MatchString(p)
}

// Allowed applies the longest matching rule; allow wins a tie.
func (r *Robots) Allowed(u *url.URL) bool {
	if r == nil {
		return true
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	best, allowed := -1, true
	for _, d := range r.disallow {
		if robotsMatch(d, p) && len(d) > best {
			best, allowed = len(d), false
		}
	}
	for _, a := range r.allow {
		if robotsMatch(a, p) && len(a) >= best {
			best, allowed = len(a), true
		}
	}
	return allowed
}

func fetchRobots(ctx context.Context, c *http.Client, origin *url.URL, ua string) *Robots {
	req, err := http.NewRequestWithContext(ctx, "GET", origin.Scheme+"://"+origin.Host+"/robots.txt", nil)
	if err != nil {
		return &Robots{}
	}
	req.Header.Set("User-Agent", ua)
	resp, err := c.Do(req)
	if err != nil {
		return &Robots{}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return &Robots{}
	}
	return ParseRobots(resp.Body)
}

// fetchSitemap returns page addresses from a sitemap or a sitemap index
// (one level deep).
func fetchSitemap(ctx context.Context, c *http.Client, sitemapURL, ua string, limit int) ([]string, error) {
	var out []string
	var get func(u string, depth int) error
	get = func(u string, depth int) error {
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", ua)
		resp, err := c.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var doc struct {
			XMLName  xml.Name
			URLs     []string `xml:"url>loc"`
			Sitemaps []string `xml:"sitemap>loc"`
		}
		if err := xml.NewDecoder(io.LimitReader(resp.Body, 50<<20)).Decode(&doc); err != nil {
			return err
		}
		for _, l := range doc.URLs {
			if len(out) >= limit {
				return nil
			}
			out = append(out, strings.TrimSpace(l))
		}
		if depth == 0 {
			for _, s := range doc.Sitemaps {
				if len(out) >= limit {
					return nil
				}
				_ = get(strings.TrimSpace(s), 1)
			}
		}
		return nil
	}
	err := get(sitemapURL, 0)
	return out, err
}
