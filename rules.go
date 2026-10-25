package pxta

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Leak is a piece of personal or sensitive data found in a request.
type Leak struct {
	Rule     string `json:"rule"`
	Key      string `json:"key"`
	Value    string `json:"value"`
	What     string `json:"what"`
	Category string `json:"category,omitempty"`
	InURL    bool   `json:"in_page_address,omitempty"`
}

// Leak rules. The names appear in findings.json.
const (
	RuleEmail     = "email"
	RuleEmailHash = "email_hash"
	RulePhone     = "phone"
	RulePhoneHash = "phone_hash"
	RuleName      = "name"
	RuleNameHash  = "name_hash"
	RuleUserHash  = "customer_data_hash"
	RuleUserID    = "user_id"
	RuleSearch    = "search_term"
	RuleSensitive = "sensitive_page"
)

var (
	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})*\.[A-Za-z]{2,24}`)
	hex64Re = regexp.MustCompile(`(?i)(?:^|[^0-9a-f])([0-9a-f]{64})(?:$|[^0-9a-f])`)
	hex32Re = regexp.MustCompile(`(?i)(?:^|[^0-9a-f])([0-9a-f]{32})(?:$|[^0-9a-f])`)
	phoneRe = regexp.MustCompile(`^\+?[0-9][0-9 ()\-.]{6,20}[0-9]$`)
	wordRe  = regexp.MustCompile(`[\p{L}\p{N}]+`)
)

// Emails is the set of email addresses PXTA knows about on a site: given on
// the command line, typed into forms by PXTA, or seen on its pages. Their
// hashes are recognised in tracker requests.
type Emails struct {
	addr map[string]bool
	hash map[string]string // lowercase hex hash -> "SHA-256" or "MD5" of addr
	of   map[string]string // hash -> address
}

func NewEmails() *Emails {
	return &Emails{addr: map[string]bool{}, hash: map[string]string{}, of: map[string]string{}}
}

// Add records an address and its hashes (as tags normalise it: trimmed,
// lower case).
func (e *Emails) Add(addr string) {
	a := strings.ToLower(strings.TrimSpace(addr))
	if a == "" || e.addr[a] || !emailRe.MatchString(a) {
		return
	}
	e.addr[a] = true
	s := sha256.Sum256([]byte(a))
	m := md5.Sum([]byte(a))
	e.hash[hex.EncodeToString(s[:])], e.of[hex.EncodeToString(s[:])] = "SHA-256", a
	e.hash[hex.EncodeToString(m[:])], e.of[hex.EncodeToString(m[:])] = "MD5", a
}

func (e *Emails) List() []string {
	var l []string
	for a := range e.addr {
		l = append(l, a)
	}
	sort.Strings(l)
	return l
}

// searchKeys are the query parameters sites usually use for their own search.
var searchKeys = map[string]bool{"q": true, "s": true, "query": true, "search": true, "search_query": true, "searchterm": true,
	"keyword": true, "keywords": true, "term": true, "k": true, "text": true, "find": true}

// SearchTerms returns the site-search terms in a page address.
func SearchTerms(pageURL string) []string {
	u, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	var out []string
	for k, vs := range u.Query() {
		if !searchKeys[strings.ToLower(k)] {
			continue
		}
		for _, v := range vs {
			if v = strings.TrimSpace(v); len([]rune(v)) >= 3 {
				out = append(out, v)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Sensitive words, matched against whole words of a page address or title.
// Two-word phrases are written with a hyphen and match "mental-health",
// "mental_health" and "mental health" alike.
var sensitiveWords = map[string][]string{
	"health": {"symptom", "symptoms", "diagnosis", "diagnose", "treatment", "treatments", "therapy", "therapist", "cancer", "oncology",
		"hiv", "aids", "std", "stds", "sti", "stis", "pregnancy", "pregnant", "fertility", "ivf", "abortion", "contraception", "miscarriage",
		"depression", "anxiety", "bipolar", "schizophrenia", "adhd", "autism", "addiction", "rehab", "overdose", "diabetes", "insulin",
		"prescription", "prescriptions", "pharmacy", "medication", "medications", "psychiatry", "psychiatrist", "psychologist",
		"counseling", "counselling", "dermatology", "cardiology", "urology", "gynecology", "gynaecology", "chemotherapy", "dementia",
		"alzheimers", "epilepsy", "hepatitis", "transplant", "dialysis", "disability", "suicide", "eating-disorder", "mental-health",
		"sexual-health", "patient", "patients", "clinic", "condition", "conditions"},
	"finance": {"debt", "debts", "bankruptcy", "bankrupt", "overdraft", "overdrawn", "payday", "foreclosure", "repossession",
		"collections", "arrears", "insolvency", "debt-relief", "debt-consolidation", "credit-repair", "bad-credit", "eviction",
		"iva", "defaulted"},
	"account": {"checkout", "order-confirmation", "order-confirmed", "order-complete", "thank-you", "thankyou", "receipt",
		"my-account", "account", "invoice", "password-reset", "reset-password", "confirmation"},
}

var sensitiveIndex = func() map[string]string {
	m := map[string]string{}
	for cat, ws := range sensitiveWords {
		for _, w := range ws {
			m[w] = cat
		}
	}
	return m
}()

// SensitiveCategory says whether a page address or title is about health,
// money trouble or a customer account, and the word that showed it.
func SensitiveCategory(s string) (category, word string) {
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		s = u.EscapedPath() + " " + u.RawQuery
		if p, err := url.PathUnescape(s); err == nil {
			s = p
		}
	}
	words := wordRe.FindAllString(strings.ToLower(s), -1)
	// Health first: a page that is both about health and a checkout is a
	// health page.
	best, bestWord := "", ""
	rank := map[string]int{"health": 3, "finance": 2, "account": 1}
	try := func(w string) {
		if c, ok := sensitiveIndex[w]; ok && rank[c] > rank[best] {
			best, bestWord = c, w
		}
	}
	for i, w := range words {
		try(w)
		if i+1 < len(words) {
			try(w + "-" + words[i+1])
		}
	}
	return best, bestWord
}

// unescapeAll undoes up to three rounds of percent-encoding. It leaves "+"
// alone: values arrive already decoded once, and a "+" in a phone number is
// a plus.
func unescapeAll(s string) string {
	for i := 0; i < 3; i++ {
		u, err := url.PathUnescape(s)
		if err != nil || u == s {
			break
		}
		s = u
	}
	return s
}

var nameKeys = map[string]bool{"fn": true, "ln": true, "first_name": true, "last_name": true, "firstname": true, "lastname": true,
	"fullname": true, "full_name": true, "given_name": true, "family_name": true, "surname": true, "name_first": true, "name_last": true}

var phoneKeys = map[string]bool{"ph": true, "phone": true, "tel": true, "telephone": true, "mobile": true, "phone_number": true, "phonenumber": true, "cell": true}

func lastKeyPart(key string) string {
	k := key
	if i := strings.LastIndexAny(k, ">.#"); i >= 0 {
		k = k[i+1:]
	}
	if i := strings.Index(k, "["); i > 0 && strings.HasSuffix(k, "]") {
		k = strings.TrimSuffix(k[i+1:], "]")
	}
	return strings.ToLower(k)
}

// FindLeaks applies every data rule to a decoded request. pageURL is the
// page the request came from; the site host tells unclassified requests'
// page addresses apart from other URLs.
func FindLeaks(ps []Param, pageURL string, emails *Emails) []Leak {
	var out []Leak
	seen := map[string]int{}
	add := func(l Leak) {
		sig := l.Rule + "\x00" + strings.ToLower(l.Value)
		if l.Rule == RuleSensitive {
			// One sensitive-page leak per category: a page's address and its
			// title saying the same thing are one finding.
			sig = l.Rule + "\x00" + strings.SplitN(l.Category, ":", 2)[0]
		}
		if i, ok := seen[sig]; ok {
			// Keep the most telling version: inside the page address beats
			// somewhere in a blob.
			if l.InURL && !out[i].InURL {
				out[i] = l
			}
			return
		}
		seen[sig] = len(out)
		out = append(out, l)
	}
	kinds := map[string]string{}
	for _, p := range ps {
		if p.Kind != "" {
			kinds[baseKey(p.Key)] = p.Kind
		}
	}
	inURL := func(p Param) bool {
		if p.Kind == KindPageURL || p.Kind == KindReferrer {
			return true
		}
		pk := parentKey(p.Key)
		return pk != "" && (kinds[pk] == KindPageURL || kinds[pk] == KindReferrer)
	}
	terms := SearchTerms(pageURL)
	for _, p := range ps {
		v := p.Value
		if strings.TrimSpace(v) == "" {
			continue
		}
		uv := unescapeAll(v)
		lk := lastKeyPart(p.Key)
		// Plain email addresses, in any URL encoding.
		for _, m := range emailRe.FindAllString(uv, 3) {
			emails.Add(m)
			add(Leak{Rule: RuleEmail, Key: p.Key, Value: strings.ToLower(m), What: "an email address", InURL: inURL(p)})
		}
		// Hashes of an email address PXTA knows.
		matched := false
		for _, re := range []*regexp.Regexp{hex64Re, hex32Re} {
			for _, m := range re.FindAllStringSubmatch(uv, 4) {
				h := strings.ToLower(m[1])
				if algo, ok := emails.hash[h]; ok {
					matched = true
					add(Leak{Rule: RuleEmailHash, Key: p.Key, Value: h, What: "a " + algo + " hash of the email address " + emails.of[h]})
				}
			}
		}
		// Fields the tag itself labels as hashed customer data.
		if !matched {
			switch p.Kind {
			case KindEmailHash:
				add(Leak{Rule: RuleEmailHash, Key: p.Key, Value: v, What: "an email address, hashed"})
			case KindPhoneHash:
				add(Leak{Rule: RulePhoneHash, Key: p.Key, Value: v, What: "a phone number, hashed"})
			case KindNameHash:
				add(Leak{Rule: RuleNameHash, Key: p.Key, Value: v, What: "a name, hashed"})
			case KindUserHash:
				add(Leak{Rule: RuleUserHash, Key: p.Key, Value: v, What: "customer data, hashed"})
			}
		}
		if p.Kind == KindUserID {
			add(Leak{Rule: RuleUserID, Key: p.Key, Value: v, What: "the site's own user ID"})
		}
		if p.Kind == "" || p.Kind == KindCustom || inURL(p) {
			if phoneKeys[lk] && phoneRe.MatchString(uv) && !isHex(uv) {
				add(Leak{Rule: RulePhone, Key: p.Key, Value: uv, What: "a phone number", InURL: inURL(p)})
			}
			if nameKeys[lk] && !isHex(uv) && len([]rune(uv)) >= 2 && !strings.ContainsAny(uv, "0123456789@") {
				add(Leak{Rule: RuleName, Key: p.Key, Value: uv, What: "a name", InURL: inURL(p)})
			}
		}
		spaced := strings.ToLower(strings.ReplaceAll(uv, "+", " "))
		for _, t := range terms {
			if strings.Contains(spaced, strings.ToLower(t)) {
				add(Leak{Rule: RuleSearch, Key: p.Key, Value: t, What: "the search term “" + t + "”", InURL: inURL(p)})
			}
		}
		if p.Kind == KindPageURL || p.Kind == KindReferrer || p.Kind == KindTitle || (p.Kind == "" && parentKey(p.Key) == "" && sameSiteURL(uv, pageURL)) {
			if cat, w := SensitiveCategory(uv); cat != "" {
				what := map[string]string{"health": "the address of a page about health", "finance": "the address of a page about money trouble", "account": "the address of a checkout or account page"}[cat]
				if p.Kind == KindTitle {
					what = map[string]string{"health": "the title of a page about health", "finance": "the title of a page about money trouble", "account": "the title of a checkout or account page"}[cat]
				}
				add(Leak{Rule: RuleSensitive, Key: p.Key, Value: uv, What: what, Category: cat + ": " + w})
			}
		}
	}
	return out
}

func sameSiteURL(v, pageURL string) bool {
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		return false
	}
	pu, err := url.Parse(pageURL)
	if err != nil {
		return false
	}
	return registrableDomain(u.Hostname()) == registrableDomain(pu.Hostname())
}

var twoLevelSuffixes = map[string]bool{"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "me.uk": true, "com.au": true,
	"net.au": true, "org.au": true, "co.nz": true, "co.jp": true, "ne.jp": true, "com.br": true, "com.mx": true, "co.il": true,
	"org.il": true, "co.za": true, "co.in": true, "com.tr": true, "com.sg": true, "com.hk": true, "com.cn": true, "co.kr": true,
	"com.ar": true, "com.co": true, "com.pl": true, "com.ua": true, "co.id": true, "com.my": true, "com.ph": true, "com.vn": true}

// registrableDomain approximates the site a host belongs to: its last two
// labels, or three under common country second-level domains.
func registrableDomain(host string) string {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if strings.Count(h, ".") < 1 || isIP(h) {
		return h
	}
	parts := strings.Split(h, ".")
	n := 2
	if len(parts) >= 3 && twoLevelSuffixes[parts[len(parts)-2]+"."+parts[len(parts)-1]] {
		n = 3
	}
	if len(parts) < n {
		return h
	}
	return strings.Join(parts[len(parts)-n:], ".")
}

func isIP(h string) bool {
	if strings.Contains(h, ":") {
		return true
	}
	for _, r := range h {
		if !(r >= '0' && r <= '9' || r == '.') {
			return false
		}
	}
	return true
}

// ConsentModeState reads Google's gcs parameter ("G1" + ad_storage +
// analytics_storage, each 1 granted, 0 denied, "-" not set).
func ConsentModeState(gcs string) (ad, analytics string, ok bool) {
	if len(gcs) != 4 || !strings.HasPrefix(gcs, "G1") {
		return "", "", false
	}
	word := func(c byte) string {
		switch c {
		case '1':
			return "granted"
		case '0':
			return "denied"
		}
		return "not set"
	}
	return word(gcs[2]), word(gcs[3]), true
}
