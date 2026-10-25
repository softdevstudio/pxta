package pxta

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const janeSHA = "8c87b489ce35cf2e2f39f80e282cb2e804932a56a213983eeeb428407d43b52d"

func mustCatalog(t *testing.T) *Catalog {
	t.Helper()
	c, err := LoadCatalog("")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCatalogSamples(t *testing.T) {
	cat := mustCatalog(t)
	if len(cat.Trackers) != 10 {
		t.Fatalf("catalog has %d trackers, want 10", len(cat.Trackers))
	}
	for _, tr := range cat.Trackers {
		t.Run(tr.ID, func(t *testing.T) {
			if tr.Sample == nil {
				t.Fatal("no sample request")
			}
			got, collect := cat.Match(tr.Sample.URL)
			if got != tr {
				t.Fatalf("sample matched %v, want %s", got, tr.ID)
			}
			if collect == tr.Sample.Script {
				t.Fatalf("collect=%v for a sample with script=%v", collect, tr.Sample.Script)
			}
			if tr.Sample.Script {
				return
			}
			ps := DecodeRequest(tr.Sample.URL, tr.Sample.Body, "")
			Describe(tr, ps)
			kinds := map[string]bool{}
			for _, p := range ps {
				kinds[p.Kind] = true
			}
			if !kinds[KindAccount] {
				t.Errorf("no account ID decoded: %+v", ps)
			}
			if !kinds[KindPageURL] && !kinds[KindEvent] {
				t.Errorf("neither page address nor event decoded: %+v", ps)
			}
			emails := NewEmails()
			emails.Add("jane@example.com")
			leaks := FindLeaks(ps, "https://shop.example/", emails)
			if len(leaks) == 0 {
				t.Errorf("sample shows no leak, but every sample carries one: %+v", ps)
			}
		})
	}
}

func TestCatalogRejectsBadEntries(t *testing.T) {
	for _, bad := range []string{
		`{"id":"x","name":"X","vendor":"V"}`,
		`{"id":"x","name":"X","vendor":"V","endpoints":[{"host":"a.com","path":"nope"}]}`,
		`{"id":"x","name":"X","vendor":"V","endpoints":[{"host":"a.com","path":"/c"}],"params":{"a":{"kind":"secret"}}}`,
		`{"id":"x","name":"X","vendor":"V","endpoints":[{"host":"a.com","path":"/c"}],"surprise":1}`,
	} {
		if _, err := parseTracker([]byte(bad), "t.json"); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestMatch(t *testing.T) {
	cat := mustCatalog(t)
	cases := []struct {
		url     string
		id      string
		collect bool
	}{
		{"https://www.facebook.com/tr/?id=1&ev=PageView", "meta-pixel", true},
		{"https://facebook.com/tr?id=1", "meta-pixel", true},
		{"https://connect.facebook.net/en_US/fbevents.js", "meta-pixel", false},
		{"https://connect.facebook.net/signals/config/123?v=2.9", "meta-pixel", false},
		{"https://www.facebook.com/translate", "", false},
		{"https://notfacebook.com/tr", "", false},
		{"https://region1.google-analytics.com/g/collect?v=2", "google-analytics-4", true},
		{"https://www.googletagmanager.com/gtag/js?id=G-1", "google-analytics-4", false},
		{"https://www.googletagmanager.com/gtm.js?id=GTM-1", "google-tag-manager", false},
		{"https://analytics.tiktok.com/api/v2/pixel", "tiktok-pixel", true},
		{"https://px.ads.linkedin.com/collect/?pid=1", "linkedin-insight", true},
		{"https://bat.bing.com/action/0?ti=1", "microsoft-uet", true},
		{"https://ct.pinterest.com/v3/?tid=1", "pinterest-tag", true},
		{"https://tr.snapchat.com/p", "snap-pixel", true},
		{"https://t.co/i/adsct?txn_id=1", "x-pixel", true},
		{"https://shop.example/index.js", "", false},
	}
	for _, c := range cases {
		tr, collect := cat.Match(c.url)
		id := ""
		if tr != nil {
			id = tr.ID
		}
		if id != c.id || collect != c.collect {
			t.Errorf("%s: got %q collect=%v, want %q collect=%v", c.url, id, collect, c.id, c.collect)
		}
	}
}

func leakRules(ls []Leak) map[string]bool {
	m := map[string]bool{}
	for _, l := range ls {
		m[l.Rule] = true
	}
	return m
}

// Every encoding the README promises must be caught.
func TestEmailEncodings(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte("jane@example.com"))
	b64url := base64.RawURLEncoding.EncodeToString([]byte(`{"email":"jane@example.com"}`))
	cases := map[string]struct{ url, body string }{
		"plain query":            {"https://t.example/c?e=jane@example.com", ""},
		"url-encoded":            {"https://t.example/c?e=jane%40example.com", ""},
		"double-encoded":         {"https://t.example/c?e=jane%2540example.com", ""},
		"inside page address":    {"https://t.example/c?dl=" + url.QueryEscape("https://shop.example/thanks?email=jane%40example.com"), ""},
		"base64":                 {"https://t.example/c?x=" + url.QueryEscape(b64), ""},
		"base64 JSON":            {"https://t.example/c?x=" + b64url, ""},
		"JSON body":              {"https://t.example/c", `{"user":{"contact":"jane@example.com"}}`},
		"JSON inside form field": {"https://t.example/c", "data=" + url.QueryEscape(`{"a":[{"b":"jane@example.com"}]}`)},
		"form body":              {"https://t.example/c", "a=1&mail=jane%40example.com&b=2"},
		"multi-line body":        {"https://t.example/c", "en=page_view\nen=sign_up&ep.mail=jane%40example.com"},
		"JSON lines body":        {"https://t.example/c", "{\"a\":1}\n{\"user\":\"jane@example.com\"}"},
		"text body":              {"https://t.example/c", "user jane@example.com signed up"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			ps := DecodeRequest(c.url, c.body, "")
			ls := FindLeaks(ps, "https://shop.example/", NewEmails())
			found := false
			for _, l := range ls {
				if l.Rule == RuleEmail && l.Value == "jane@example.com" {
					found = true
				}
			}
			if !found {
				t.Fatalf("email not found; params %+v, leaks %+v", ps, ls)
			}
		})
	}
}

func TestEmailHashes(t *testing.T) {
	emails := NewEmails()
	emails.Add(" Jane@Example.com ")
	for name, u := range map[string]string{
		"sha256 lower":    "https://t.example/c?h=" + janeSHA,
		"sha256 upper":    "https://t.example/c?h=" + strings.ToUpper(janeSHA),
		"md5":             "https://t.example/c?h=9e26471d35a78862c17e467d87cddedf",
		"inside a string": "https://t.example/c?em=tv.1~em." + janeSHA + "~ph.x",
	} {
		ls := FindLeaks(DecodeRequest(u, "", ""), "https://shop.example/", emails)
		if !leakRules(ls)[RuleEmailHash] || !strings.Contains(ls[0].What, "jane@example.com") {
			t.Errorf("%s: %+v", name, ls)
		}
	}
	// A hash of an address PXTA doesn't know is not flagged on its own...
	ls := FindLeaks(DecodeRequest("https://t.example/c?h="+strings.Repeat("ab", 32), "", ""), "https://shop.example/", emails)
	if len(ls) != 0 {
		t.Errorf("unknown hash flagged: %+v", ls)
	}
	// ...but a field the tag calls a hashed email is.
	cat := mustCatalog(t)
	tr := trackerOrNil(cat, "meta-pixel")
	ps := DecodeRequest("https://www.facebook.com/tr?id=1&ud[em]="+strings.Repeat("ab", 32), "", "")
	Describe(tr, ps)
	if !leakRules(FindLeaks(ps, "https://shop.example/", emails))[RuleEmailHash] {
		t.Error("ud[em] not flagged")
	}
}

func TestOtherRules(t *testing.T) {
	emails := NewEmails()
	page := "https://shop.example/search?q=flu+symptoms"
	ps := DecodeRequest("https://t.example/c?ph=%2B44%2020%207946%200958&fn=Jane&dl="+url.QueryEscape(page), "", "")
	got := leakRules(FindLeaks(ps, page, emails))
	for _, r := range []string{RulePhone, RuleName, RuleSearch} {
		if !got[r] {
			t.Errorf("rule %s did not fire: %v", r, got)
		}
	}
	// Numbers and IDs that only look like data stay quiet.
	quiet := DecodeRequest("https://t.example/c?ts=1761400000000&fn=a1b2c3&id=12345678&sw=1920", "", "")
	if ls := FindLeaks(quiet, "https://shop.example/", emails); len(ls) != 0 {
		t.Errorf("false positives: %+v", ls)
	}
}

func TestSensitiveCategory(t *testing.T) {
	cases := map[string]string{
		"https://clinic.example/conditions/anxiety":          "health",
		"https://shop.example/collections/summer-dresses":    "",
		"https://shop.example/pages/terms-and-conditions":    "",
		"https://audio.example/blog/hearing-aids-review":     "",
		"Opening hours | Cedar Valley Clinic":                "",
		"https://agency.example/debt-collections/help":       "finance",
		"https://clinic.example/book?service=mental-health":  "health",
		"https://bank.example/loans/debt-consolidation":      "finance",
		"https://shop.example/checkout/order-confirmation":   "account",
		"https://shop.example/checkout?item=pregnancy-test":  "health",
		"https://shop.example/products/blue-shirt":           "",
		"https://shop.example/accountants":                   "",
		"Anxiety treatment that works | Cedar Valley Clinic": "health",
	}
	for in, want := range cases {
		if got, _ := SensitiveCategory(in); got != want {
			t.Errorf("%s: got %q, want %q", in, got, want)
		}
	}
}

func TestConsentModeState(t *testing.T) {
	ad, an, ok := ConsentModeState("G100")
	if !ok || ad != "denied" || an != "denied" {
		t.Error("G100", ad, an, ok)
	}
	ad, an, ok = ConsentModeState("G111")
	if !ok || ad != "granted" || an != "granted" {
		t.Error("G111", ad, an, ok)
	}
	if _, _, ok := ConsentModeState("X1"); ok {
		t.Error("accepted junk")
	}
}

func TestRobots(t *testing.T) {
	r := ParseRobots(strings.NewReader(`
User-agent: Googlebot
Disallow: /

User-agent: *
Disallow: /private
Disallow: /*.pdf$
Allow: /private/ok

User-agent: pxta-other
Disallow: /x`))
	for p, want := range map[string]bool{"/": true, "/shop": true, "/private": false, "/private/a": false, "/private/ok": true,
		"/doc.pdf": false, "/doc.pdf?x": true} {
		u, _ := url.Parse("https://s.example" + p)
		if got := r.Allowed(u); got != want {
			t.Errorf("%s: got %v want %v", p, got, want)
		}
	}
	own := ParseRobots(strings.NewReader("User-agent: *\nDisallow: /\n\nUser-agent: pxta\nDisallow: /admin\n"))
	u, _ := url.Parse("https://s.example/shop")
	if !own.Allowed(u) {
		t.Error("a pxta group should win over *")
	}
}

func TestNormalizeLink(t *testing.T) {
	o, _ := url.Parse("https://shop.example/")
	for in, want := range map[string]string{
		"https://shop.example/a#top":      "https://shop.example/a",
		"https://shop.example":            "https://shop.example/",
		"https://other.example/a":         "",
		"http://shop.example/a":           "https://shop.example/a",
		"https://www.shop.example/b":      "https://shop.example/b",
		"https://shop.example/menu.pdf":   "",
		"https://shop.example/logout":     "",
		"mailto:a@shop.example":           "",
		"https://shop.example/p?id=1&x=2": "https://shop.example/p?id=1&x=2",
	} {
		got, ok := normalizeLink(in, o)
		if !ok {
			got = ""
		}
		if got != want {
			t.Errorf("%s: got %q want %q", in, got, want)
		}
	}
}

func req(pass string, page int, u, body string) Request {
	return Request{Pass: pass, Page: page, URL: u, Method: map[bool]string{true: "POST", false: "GET"}[body != ""], Body: body,
		Type: "Image", Target: "page", Phase: "load", Time: time.Unix(1761400000, 0).UTC()}
}

func TestAnalyze(t *testing.T) {
	cat := mustCatalog(t)
	visits := []Visit{
		{Pass: PassNone, Page: 0, URL: "https://shop.example/"},
		{Pass: PassNone, Page: 1, URL: "https://shop.example/checkout/confirm?email=jane%40example.com"},
		{Pass: PassReject, Page: 0, URL: "https://shop.example/"},
		{Pass: PassReject, Page: 1, URL: "https://shop.example/checkout/confirm?email=jane%40example.com"},
		{Pass: PassAccept, Page: 1, URL: "https://shop.example/checkout/confirm?email=jane%40example.com"},
	}
	conf := url.QueryEscape("https://shop.example/checkout/confirm?email=jane%40example.com")
	reqs := []Request{
		req(PassNone, 0, "https://connect.facebook.net/en_US/fbevents.js", ""),
		req(PassNone, 0, "https://www.facebook.com/tr/?id=1&ev=PageView&dl=https%3A%2F%2Fshop.example%2F", ""),
		req(PassNone, 0, "https://www.facebook.com/tr/?id=1&ev=PageView&dl=https%3A%2F%2Fshop.example%2F", ""),
		req(PassNone, 1, "https://www.facebook.com/tr/?id=1&ev=Purchase&dl="+conf, ""),
		req(PassNone, 1, "https://region1.google-analytics.com/g/collect?v=2&tid=G-1&gcs=G111&dl="+conf, ""),
		req(PassReject, 1, "https://region1.google-analytics.com/g/collect?v=2&tid=G-1&gcs=G100&uid=customer-42&dl="+url.QueryEscape("https://shop.example/checkout/confirm"), ""),
		req(PassAccept, 1, "https://www.facebook.com/tr/?id=1&ev=Purchase&ud[em]="+janeSHA, ""),
		req(PassNone, 0, "https://beacon.unknown-vendor.example/v1/hit", `{"page":"https://shop.example/","visitor":"abc"}`),
		req(PassNone, 0, "https://cdn.shop.example/app.js", ""),
	}
	reqs[7].Type = "Ping"
	a := Analyze(cat, visits, reqs, NewEmails(), "pxta audit")
	byCode := map[string][]*Finding{}
	for _, f := range a.Findings {
		byCode[f.Code] = append(byCode[f.Code], f)
	}
	want := map[string]int{CodeTrackerBeforeConsent: 3, CodeTrackerAfterReject: 1, CodePersonalData: 4, CodeSensitivePage: 3,
		CodeConsentModeGranted: 1, CodeConsentModeMismatch: 1}
	for code, n := range want {
		if len(byCode[code]) != n {
			for _, f := range byCode[code] {
				t.Log(f.Sentence)
			}
			t.Errorf("%s: %d findings, want %d", code, len(byCode[code]), n)
		}
	}
	// The repeated PageView is one finding seen twice.
	for _, f := range byCode[CodeTrackerBeforeConsent] {
		if f.Page == "/" && f.Name == "Meta Pixel" && f.Count != 2 {
			t.Errorf("PageView count %d, want 2", f.Count)
		}
	}
	var sentence string
	for _, f := range byCode[CodePersonalData] {
		if f.Pass == PassNone && f.Name == "Meta Pixel" {
			sentence = f.Sentence
			if f.Severity != SevHigh {
				t.Errorf("severity %s, want high", f.Severity)
			}
		}
		if f.Pass == PassAccept && f.Severity != SevLow {
			t.Errorf("accepted pass severity %s, want low", f.Severity)
		}
	}
	wantS := "On /checkout/confirm?email=jane@example.com, the Meta Pixel sent an email address inside the page address before the consent banner was answered."
	if sentence != wantS {
		t.Errorf("sentence:\n got %q\nwant %q", sentence, wantS)
	}
	// The hash sent after accept matches the address seen earlier.
	found := false
	for _, f := range byCode[CodePersonalData] {
		if f.Pass == PassAccept && strings.Contains(f.Sentence, "SHA-256 hash of the email address jane@example.com") {
			found = true
		}
	}
	if !found {
		t.Error("hash after accept not matched to the address")
	}
	unclassified := false
	for _, tu := range a.Trackers {
		if tu.ID == "unclassified:beacon.unknown-vendor.example" {
			unclassified = true
		}
		if strings.Contains(tu.ID, "cdn.shop.example") {
			t.Error("first-party script listed as a tracker")
		}
	}
	if !unclassified {
		t.Error("unclassified beacon missing from the inventory")
	}
	if a.Counts[SevHigh] == 0 || a.Counts[SevMedium] == 0 || a.Counts[SevLow] == 0 {
		t.Errorf("counts %v", a.Counts)
	}
	if !strings.HasPrefix(a.Findings[0].Code, "personal-data") || a.Findings[0].Severity != SevHigh {
		t.Errorf("first finding is %s/%s, want the highest", a.Findings[0].Code, a.Findings[0].Severity)
	}
}

func TestRenderEscapes(t *testing.T) {
	cat := mustCatalog(t)
	visits := []Visit{{Pass: PassNoBanner, Page: 0, URL: "https://shop.example/"}}
	evil := url.QueryEscape("https://shop.example/?q=<script>alert(1)</script>&email=jane@example.com")
	reqs := []Request{req(PassNoBanner, 0, "https://www.facebook.com/tr?id=1&ev=PageView&dl="+evil, "")}
	r := &Result{Tool: "pxta", Version: Version, Site: "https://shop.example/", Passes: []string{PassNoBanner}, Pages: visits, requests: reqs,
		Started: time.Now(), Finished: time.Now()}
	r.Analysis = Analyze(cat, visits, reqs, NewEmails(), "")
	b, err := RenderHTML(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "<script>alert") {
		t.Fatal("page data reached the report unescaped")
	}
	if strings.Contains(s, "<script") || strings.Contains(s, "http://") && strings.Contains(s, "<link") {
		t.Fatal("the report must not load or run anything")
	}
	if !strings.Contains(s, "an email address inside the page address") {
		t.Fatal("finding sentence missing from the report")
	}
	har, err := buildHAR(r)
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	if err := json.Unmarshal(har, &h); err != nil {
		t.Fatal(err)
	}
}

// fakeDevTools is a WebSocket server speaking just enough of the protocol to
// test the client: it answers every command with its own params, sends an
// event after each, splits large answers into fragments, and pings.
func fakeDevTools(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Sec-WebSocket-Key")
		h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
			base64.StdEncoding.EncodeToString(h[:]) + "\r\n\r\n")
		rw.Flush()
		send := func(op byte, fin bool, p []byte) {
			b := []byte{op}
			if fin {
				b[0] |= 0x80
			}
			switch {
			case len(p) < 126:
				b = append(b, byte(len(p)))
			case len(p) <= 0xFFFF:
				b = append(b, 126, byte(len(p)>>8), byte(len(p)))
			default:
				var x [8]byte
				binary.BigEndian.PutUint64(x[:], uint64(len(p)))
				b = append(append(b, 127), x[:]...)
			}
			conn.Write(append(b, p...))
		}
		br := bufio.NewReader(rw)
		for {
			var hd [2]byte
			if _, err := io.ReadFull(br, hd[:]); err != nil {
				return
			}
			n := int(hd[1] & 0x7F)
			if n == 126 {
				var x [2]byte
				io.ReadFull(br, x[:])
				n = int(binary.BigEndian.Uint16(x[:]))
			} else if n == 127 {
				var x [8]byte
				io.ReadFull(br, x[:])
				n = int(binary.BigEndian.Uint64(x[:]))
			}
			var mask [4]byte
			io.ReadFull(br, mask[:])
			p := make([]byte, n)
			io.ReadFull(br, p)
			for i := range p {
				p[i] ^= mask[i%4]
			}
			if hd[0]&0x0F == 0x8 {
				return
			}
			if hd[0]&0x0F != 0x1 {
				continue
			}
			var m cdpMessage
			json.Unmarshal(p, &m)
			send(0x9, true, []byte("hi")) // a ping first; the client must answer and carry on
			ev, _ := json.Marshal(cdpMessage{Method: "Test.event", SessionID: m.SessionID, Params: m.Params})
			send(0x1, true, ev)
			res, _ := json.Marshal(cdpMessage{ID: m.ID, Result: m.Params})
			if m.Method == "Test.fail" {
				res, _ = json.Marshal(cdpMessage{ID: m.ID, Error: &cdpError{Code: -32000, Message: "no such thing"}})
			}
			if len(res) > 1000 {
				half := len(res) / 2
				send(0x1, false, res[:half])
				send(0x0, true, res[half:])
			} else {
				send(0x1, true, res)
			}
		}
	}))
	t.Cleanup(srv.Close)
	return "ws://" + strings.TrimPrefix(srv.URL, "http://") + "/devtools/browser/x"
}

func TestCDPClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := DialCDP(ctx, fakeDevTools(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	events := make(chan Event, 10)
	c.Subscribe(func(e Event) { events <- e })
	var out struct {
		A string `json:"a"`
	}
	if err := c.Call(ctx, "s1", "Test.echo", map[string]string{"a": "hello"}, &out); err != nil || out.A != "hello" {
		t.Fatalf("echo: %v %q", err, out.A)
	}
	if e := <-events; e.Method != "Test.event" || e.SessionID != "s1" {
		t.Fatalf("event %+v", e)
	}
	big := strings.Repeat("x", 300000) // longer than one 64 KiB frame, and fragmented by the server
	if err := c.Call(ctx, "", "Test.echo", map[string]string{"a": big}, &out); err != nil || out.A != big {
		t.Fatalf("big echo: %v len %d", err, len(out.A))
	}
	err = c.Call(ctx, "", "Test.fail", nil, nil)
	var ce *cdpError
	if err == nil || !strings.Contains(err.Error(), "no such thing") {
		t.Fatalf("error answer: %v", err)
	}
	_ = ce
	c.Close()
	select {
	case <-c.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("Done not closed after Close")
	}
	if err := c.Call(ctx, "", "Test.echo", nil, nil); err != ErrClosed {
		t.Fatalf("call after close: %v", err)
	}
}

func TestDialRejectsNonWebSocket(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := DialCDP(ctx, "ws://"+strings.TrimPrefix(srv.URL, "http://")+"/x"); err == nil {
		t.Fatal("dialled a server that is not WebSocket")
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	if _, err := DialCDP(ctx, "ws://"+addr+"/x"); err == nil {
		t.Fatal("dialled a closed port")
	}
}

func TestIsEmail(t *testing.T) {
	for in, want := range map[string]bool{"jane@example.com": true, "hero@2x.png": false, "logo@3x.webp": false,
		"bundle@1.2.3.js": false, "a.b@shop.co.uk": true} {
		if got := isEmail(in); got != want {
			t.Errorf("%s: got %v", in, got)
		}
	}
}

func TestContainsWords(t *testing.T) {
	for _, c := range []struct {
		s, p string
		want bool
	}{{"configured", "red", false}, {"red shoes", "red", true}, {"q=red", "red", true}, {"wool socks sale", "wool socks", true},
		{"woolsocks", "wool socks", false}, {"über alles", "über", true}} {
		if got := containsWords(c.s, c.p); got != c.want {
			t.Errorf("%q in %q: got %v", c.p, c.s, got)
		}
	}
}
