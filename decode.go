package pxta

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

var base64Std = base64.StdEncoding

// Param is one decoded value from a request. Key shows where it came from:
// "dl" is a query parameter, "context.page.url" a JSON field, "dl>email" the
// email parameter inside the URL carried in dl, "x#base64" the base64-decoded
// form of x, "body.3>en" a line of a multi-line body.
type Param struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Meaning string `json:"meaning,omitempty"`
	Kind    string `json:"kind,omitempty"`
	Source  string `json:"source"` // query, body, json, url, base64
}

const (
	maxParams     = 2000
	maxValueLen   = 64 << 10
	maxNestDepth  = 4
	minBase64Len  = 12
	jsonFlattenAt = 6
)

// DecodeRequest pulls every value out of a request's URL and body.
func DecodeRequest(rawURL, body, contentType string) []Param {
	d := &decoder{}
	if u, err := url.Parse(rawURL); err == nil {
		d.addQuery("", u.RawQuery, "query", 0)
	}
	if body != "" {
		d.addBody(body, contentType)
	}
	return d.out
}

type decoder struct {
	out  []Param
	seen map[string]bool
}

func (d *decoder) add(key, value, source string, depth int) {
	if len(d.out) >= maxParams {
		return
	}
	if len(value) > maxValueLen {
		value = value[:maxValueLen]
	}
	if d.seen == nil {
		d.seen = map[string]bool{}
	}
	sig := key + "\x00" + value
	if d.seen[sig] {
		return
	}
	d.seen[sig] = true
	d.out = append(d.out, Param{Key: key, Value: value, Source: source})
	if depth >= maxNestDepth {
		return
	}
	d.unpack(key, value, depth+1)
}

// unpack looks inside a value: a URL's query string, JSON, base64.
func (d *decoder) unpack(key, value string, depth int) {
	v := strings.TrimSpace(value)
	if v == "" {
		return
	}
	if (strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://")) && strings.Contains(v, "?") {
		if u, err := url.Parse(v); err == nil && u.RawQuery != "" {
			d.addQuery(key+">", u.RawQuery, "url", depth)
		}
		return
	}
	if (strings.HasPrefix(v, "{") && strings.HasSuffix(v, "}")) || (strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]")) {
		var x any
		if json.Unmarshal([]byte(v), &x) == nil {
			d.addJSON(key, x, depth)
			return
		}
	}
	if b, ok := decodeBase64Text(v); ok {
		d.add(key+"#base64", b, "base64", depth)
	}
}

func (d *decoder) addQuery(prefix, raw, source string, depth int) {
	if raw == "" {
		return
	}
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == '&' || r == ';' }) {
		k, v, _ := strings.Cut(part, "=")
		dk, err := url.QueryUnescape(k)
		if err != nil {
			dk = k
		}
		dv, err := url.QueryUnescape(v)
		if err != nil {
			dv = v
		}
		if dk == "" {
			continue
		}
		d.add(prefix+dk, dv, source, depth)
	}
}

func (d *decoder) addBody(body, contentType string) {
	b := strings.TrimSpace(body)
	ct := strings.ToLower(contentType)
	if strings.HasPrefix(b, "{") || strings.HasPrefix(b, "[") || strings.Contains(ct, "json") {
		var x any
		if json.Unmarshal([]byte(b), &x) == nil {
			d.addJSON("", x, 0)
			return
		}
		// Some tags send several JSON objects, one per line.
		lines := strings.Split(b, "\n")
		if len(lines) > 1 {
			ok := true
			for i, l := range lines {
				l = strings.TrimSpace(l)
				if l == "" {
					continue
				}
				if json.Unmarshal([]byte(l), &x) != nil {
					ok = false
					break
				}
				d.addJSON(fmt.Sprintf("body.%d>", i), x, 0)
			}
			if ok {
				return
			}
		}
	}
	if strings.Contains(b, "=") && !strings.ContainsAny(b, " \t") || strings.Contains(ct, "x-www-form-urlencoded") {
		lines := strings.Split(b, "\n")
		if len(lines) == 1 {
			d.addQuery("", b, "body", 0)
			return
		}
		// Google Analytics 4 batches: one event per line, each a query string.
		for i, l := range lines {
			if l = strings.TrimSpace(l); l != "" {
				d.addQuery(fmt.Sprintf("body.%d>", i), l, "body", 0)
			}
		}
		return
	}
	d.add("body", b, "body", 0)
}

func (d *decoder) addJSON(prefix string, x any, depth int) {
	var walk func(p string, v any, level int)
	walk = func(p string, v any, level int) {
		if len(d.out) >= maxParams {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				np := k
				if p != "" && !strings.HasSuffix(p, ">") {
					np = p + "." + k
				} else {
					np = p + k
				}
				walk(np, t[k], level+1)
			}
		case []any:
			for i, e := range t {
				walk(p+"["+strconv.Itoa(i)+"]", e, level+1)
			}
		case string:
			d.add(strings.TrimSuffix(p, ">"), t, "json", depth)
		case nil:
		default:
			d.add(strings.TrimSuffix(p, ">"), fmt.Sprint(t), "json", depth)
		}
	}
	walk(prefix, x, 0)
}

// decodeBase64Text decodes s when it is base64 of readable text.
func decodeBase64Text(s string) (string, bool) {
	if len(s) < minBase64Len || len(s) > maxValueLen {
		return "", false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '+' || r == '/' || r == '=' || r == '-' || r == '_') {
			return "", false
		}
	}
	if isHex(s) {
		return "", false // hashes are hex, not base64 text
	}
	var b []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err = enc.DecodeString(s); err == nil {
			break
		}
	}
	if err != nil || len(b) < 4 || !utf8.Valid(b) {
		return "", false
	}
	printable := 0
	for _, r := range string(b) {
		if r >= 32 && r != 127 || r == '\n' || r == '\t' {
			printable++
		}
	}
	if printable*10 < utf8.RuneCount(b)*9 {
		return "", false
	}
	return string(b), true
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

// Describe fills Meaning and Kind from the tracker's catalog entry.
func Describe(t *Tracker, ps []Param) {
	for i := range ps {
		if pi, ok := t.Info(ps[i].Key); ok {
			ps[i].Meaning, ps[i].Kind = pi.Meaning, pi.Kind
		}
	}
}
