// Package spamfilter provides Mailpit's built-in, zero-dependency heuristic
// spam detection. A set of preset rules scores every message locally (no
// external services or network requests), and optional user-defined rules
// can be loaded from a YAML configuration file. Messages reaching the score
// threshold are flagged as spam and (when enabled) auto-tagged on ingest.
package spamfilter

import (
	"bytes"
	"math"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/jhillyerd/enmime/v2"
)

const (
	defaultThreshold = 5.0
	defaultTag       = "spam"
	// maxScanLen caps the amount of body content fed to regular expressions,
	// bounding the cost of scanning very large messages.
	maxScanLen = 512 * 1024
)

// Enabled determines whether the built-in spam filter runs. It defaults to
// true and can be disabled with --disable-spam-filter / MP_DISABLE_SPAM_FILTER.
var Enabled = true

// Result is a spam filter result
//
// swagger:model SpamFilterResponse
type Result struct {
	// Whether the message is spam or not (Score >= Threshold)
	IsSpam bool
	// Total spam score based on triggered rules
	Score float64
	// Score at which a message is considered spam
	Threshold float64
	// Spam rules triggered
	Rules []Rule
}

// Rule struct
//
// swagger:model SpamFilterRule
type Rule struct {
	// Rule score (negative scores reduce the total)
	Score float64
	// Rule name / ID
	Name string
	// Rule description
	Description string
	// Whether the rule is a built-in (preset) rule
	Builtin bool
}

// matcherRule is a compiled rule evaluated against a parsed message.
type matcherRule struct {
	id          string
	description string
	score       float64
	builtin     bool
	fn          func(m *message) bool
}

// link represents a hyperlink found in the message.
type link struct {
	href string
	text string // visible anchor text (plain-text links repeat the URL)
}

// message is the normalized representation of an email used by rule matchers.
type message struct {
	from        string // lowercased From email address
	fromDomain  string
	fromName    string
	replyTo     []*mail.Address
	getHeader   func(string) string
	subject     string
	text        string
	html        string
	attachments []string // filenames of attachments & inline parts
	links       []link
}

var (
	mu             sync.RWMutex
	scoreThreshold = defaultThreshold
	spamTag        = defaultTag
	activeRules    []matcherRule
	builtInCount   int
	customCount    int
	allowList      []listEntry
	blockList      []listEntry
)

func init() {
	resetState()
}

// Check parses a raw RFC 822 message and runs the spam filter.
func Check(raw []byte) (Result, error) {
	parser := enmime.NewParser(enmime.DisableCharacterDetection(true))

	env, err := parser.ReadEnvelope(bytes.NewReader(raw))
	if err != nil {
		return Result{Threshold: Threshold(), Rules: []Rule{}}, err
	}

	return CheckEnvelope(env), nil
}

// CheckEnvelope runs the spam filter against an already-parsed enmime
// envelope. It never returns an error: rule evaluation is fully defensive so
// that message ingestion can never be interrupted by the filter.
func CheckEnvelope(env *enmime.Envelope) Result {
	res := Result{Threshold: Threshold(), Rules: []Rule{}}

	if !Enabled {
		return res
	}

	mu.RLock()
	th := scoreThreshold
	currentRules := activeRules
	allow := allowList
	block := blockList
	mu.RUnlock()

	res.Threshold = th

	msg := newMessage(env)

	// allowlisted senders short-circuit all scoring
	if matchesList(msg.from, allow) {
		return res
	}

	score := 0.0

	if matchesList(msg.from, block) {
		// blocklisted senders are always flagged as spam
		res.Rules = append(res.Rules, Rule{
			Score:       round1(th),
			Name:        "BLOCKLIST",
			Description: "Sender matches the configured blocklist",
			Builtin:     false,
		})
		score = th
	} else {
		for _, r := range currentRules {
			if r.fn(msg) {
				score += r.score
				res.Rules = append(res.Rules, Rule{
					Score:       round1(r.score),
					Name:        r.id,
					Description: r.description,
					Builtin:     r.builtin,
				})
			}
		}
	}

	res.Score = round1(score)
	res.IsSpam = res.Score >= th

	return res
}

// Threshold returns the score at/above which a message is flagged as spam.
func Threshold() float64 {
	mu.RLock()
	defer mu.RUnlock()
	return scoreThreshold
}

// Tag returns the tag applied to spam messages, or an empty string if
// auto-tagging is disabled.
func Tag() string {
	mu.RLock()
	defer mu.RUnlock()
	return spamTag
}

// RuleCounts returns the number of active built-in and custom rules.
func RuleCounts() (builtIn int, custom int) {
	mu.RLock()
	defer mu.RUnlock()
	return builtInCount, customCount
}

// newMessage builds the normalized message used by rule matchers from an
// enmime envelope.
func newMessage(env *enmime.Envelope) *message {
	m := &message{
		subject:   truncate(env.GetHeader("Subject"), 10*1024),
		text:      truncate(env.Text, maxScanLen),
		html:      truncate(env.HTML, maxScanLen),
		getHeader: env.GetHeader,
	}
	// derive links from the same truncated content so very large messages
	// cannot make link scanning disproportionally expensive
	m.links = extractLinks(m.html, m.text)

	if addrs, err := env.AddressList("From"); err == nil && len(addrs) > 0 && addrs[0] != nil {
		m.from = strings.ToLower(strings.TrimSpace(addrs[0].Address))
		m.fromName = addrs[0].Name
		m.fromDomain = emailDomain(m.from)
	}

	if addrs, err := env.AddressList("Reply-To"); err == nil {
		m.replyTo = addrs
	}

	for _, a := range env.Attachments {
		if a != nil && a.FileName != "" {
			m.attachments = append(m.attachments, a.FileName)
		}
	}
	for _, a := range env.Inlines {
		if a != nil && a.FileName != "" {
			m.attachments = append(m.attachments, a.FileName)
		}
	}

	return m
}

// header returns a (trimmed) message header value.
func (m *message) header(name string) string {
	if m.getHeader == nil {
		return ""
	}
	return strings.TrimSpace(m.getHeader(name))
}

// body returns the combined text and HTML content for content matching.
func (m *message) body() string {
	return m.text + " " + m.html
}

type listEntry struct {
	email  string // lowercased full email address (mutually exclusive with domain)
	domain string // lowercased domain, matches the domain and its subdomains
}

// matchesList reports whether the given address matches any allow/block list
// entry. Entries may be full email addresses or domains.
func matchesList(addr string, list []listEntry) bool {
	addr = strings.ToLower(strings.TrimSpace(addr))
	if addr == "" {
		return false
	}
	dom := emailDomain(addr)

	for _, e := range list {
		if e.email != "" {
			if e.email == addr {
				return true
			}
			continue
		}
		if e.domain != "" && dom != "" && (dom == e.domain || strings.HasSuffix(dom, "."+e.domain)) {
			return true
		}
	}

	return false
}

func emailDomain(addr string) string {
	if i := strings.LastIndex(addr, "@"); i >= 0 && i+1 < len(addr) {
		return strings.ToLower(strings.TrimSpace(addr[i+1:]))
	}
	return ""
}

// linkDomain returns the lowercased host portion of a URL, or an empty string.
func linkDomain(href string) string {
	u, err := url.Parse(strings.TrimSpace(href))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}

func round1(n float64) float64 {
	return math.Round(n*10) / 10
}

var (
	// anchorRE extracts href + visible text from HTML anchors.
	anchorRE = regexp.MustCompile(`(?is)<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>(.*?)</a>`)
	// rawURLRE extracts bare URLs from text content.
	rawURLRE = regexp.MustCompile(`https?://[^\s<>"'()]+`)
	// htmlTagRE strips HTML tags from visible anchor text.
	htmlTagRE = regexp.MustCompile(`(?s)<[^>]*>`)
)

// extractLinks returns the distinct http(s) links found in the message.
// Anchors carry their visible text; plain URLs repeat the URL as text.
func extractLinks(html, text string) []link {
	links := []link{}
	seen := map[string]bool{}

	add := func(href, label string) {
		href = strings.TrimSpace(htmlUnescape(href))
		lower := strings.ToLower(href)
		if href == "" || !(strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")) {
			return
		}
		if seen[href] {
			return
		}
		seen[href] = true
		label = htmlUnescape(htmlTagRE.ReplaceAllString(label, " "))
		links = append(links, link{href: href, text: strings.Join(strings.Fields(label), " ")})
	}

	for _, match := range anchorRE.FindAllStringSubmatch(html, -1) {
		href := match[1]
		if href == "" {
			href = match[2]
		}
		if href == "" {
			href = match[3]
		}
		add(href, match[4])
	}

	for _, u := range rawURLRE.FindAllString(text, -1) {
		add(u, u)
	}
	for _, u := range rawURLRE.FindAllString(html, -1) {
		add(u, u)
	}

	return links
}

// htmlUnescape decodes the few HTML entities that commonly appear in links or
// link text without pulling in an html dependency.
func htmlUnescape(s string) string {
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&#38;", "&")
	s = strings.ReplaceAll(s, "&quot;", `"`)
	s = strings.ReplaceAll(s, "&#34;", `"`)
	s = strings.ReplaceAll(s, "&#39;", `'`)
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	return s
}
