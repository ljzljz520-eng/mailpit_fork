package spamfilter

import (
	"net"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// emailRE finds email addresses embedded in free text (e.g. display names).
var emailRE = regexp.MustCompile(`[\w.+-]+@[\w-]+(?:\.[\w-]+)+`)

// repeatedPunctuationRE matches runs of 3+ spammy punctuation chars
// (RE2 has no backreferences, so a character class is used; "." is deliberately
// excluded so legitimate ellipses do not trigger the rule).
var repeatedPunctuationRE = regexp.MustCompile(`[!?$]{3,}`)

// htmlFormRE matches an HTML form opening tag.
var htmlFormRE = regexp.MustCompile(`(?is)<form\b[^>]*>`)

// htmlPasswordRE matches an HTML password input.
var htmlPasswordRE = regexp.MustCompile(`(?is)<input\b[^>]*\btype\s*=\s*["']?\s*password`)

// doubleExtRE matches a benign-looking extension followed by an executable one.
var doubleExtRE = regexp.MustCompile(`(?i)\.[a-z0-9]{1,5}\.(?:exe|scr|js|vbs|bat|cmd|com|pif|jar|msi|ps1|hta|ws|wsf|wsh|application|gadget)$`)

// executableExtensions are attachment extensions commonly used by malware.
var executableExtensions = map[string]bool{
	"exe": true, "scr": true, "js": true, "vbs": true, "bat": true,
	"cmd": true, "com": true, "pif": true, "jar": true, "msi": true,
	"ps1": true, "hta": true, "ws": true, "wsf": true, "wsh": true,
	"application": true, "gadget": true,
}

// urlShorteners are common link-shortening hostnames.
var urlShorteners = map[string]bool{
	"bit.ly": true, "tinyurl.com": true, "t.co": true, "ow.ly": true,
	"is.gd": true, "cutt.ly": true, "goo.gl": true, "buff.ly": true,
	"rebrand.ly": true, "shorturl.at": true, "tiny.cc": true, "rb.gy": true,
	"cli.re": true, "shorte.st": true,
}

// spamPhrases are high-signal spam phrases matched with word boundaries.
var spamPhrases = []string{
	// pharmaceuticals
	`viagra`, `cialis`, `levitra`, `phentermine`, `xanax`, `online pharmacy`, `cheap meds?`, `weight loss pills?`, `lose weight fast`,
	// lottery / scams
	`lottery`, `sweepstakes?`, `you have won`, `you'?ve won`, `you are a winner`, `you'?re a winner`, `prize claim`, `claim your prize`, `dear (?:winner|lucky)`,
	// money scams
	`free gift cards?`, `free money`, `money order`, `wire transfer`, `bank transfer`, `nigerian prince`, `foreign prince`, `west african`, `overseas beneficiary`,
	// investment / work scams
	`crypto(?:currency)? investment`, `bitcoin investment`, `invest in crypto`, `guaranteed returns?`, `double your (?:money|investment|income)`, `get rich quick`, `make money fast`,
	// aggressive marketing
	`act now`, `limited time offer`, `100%\s?free`, `risk[- ]free`, `no cost to you`, `pre[- ]approved loan`, `refinance your (?:home|mortgage)`,
}

// spamPhraseRE matches any of the spam phrases (case-insensitive, word-bounded).
var spamPhraseRE = regexp.MustCompile(`(?i)(?:\b|^)(?:` + strings.Join(spamPhrases, "|") + `)(?:\b|$)`)

// builtinRule defines a preset heuristic rule.
type builtinRule struct {
	id          string
	description string
	score       float64
	fn          func(m *message) bool
}

// builtinRules returns the fresh set of preset rules.
func builtinRules() []matcherRule {
	defs := []builtinRule{
		// --- Headers ---
		{
			id: "MISSING_FROM", score: 2.0,
			description: "Message has no From header",
			fn:          func(m *message) bool { return m.from == "" && strings.TrimSpace(m.fromName) == "" },
		},
		{
			id: "MISSING_DATE", score: 1.0,
			description: "Message has no Date header",
			fn:          func(m *message) bool { return m.header("Date") == "" },
		},
		{
			id: "MISSING_MESSAGE_ID", score: 1.0,
			description: "Message has no Message-ID header",
			fn:          func(m *message) bool { return m.header("Message-ID") == "" },
		},
		{
			id: "FORGED_FROM_DISPLAY_NAME", score: 2.5,
			description: "From display name contains an email address with a different domain than the sender",
			fn:          forgedFromDisplayName,
		},
		{
			id: "REPLYTO_DOMAIN_MISMATCH", score: 1.5,
			description: "Reply-To address domain does not match the From domain",
			fn:          replyToDomainMismatch,
		},
		{
			id: "X_SPAM_FLAG_SET", score: 5.0,
			description: "Message is already flagged as spam by an upstream filter",
			fn:          xSpamFlagSet,
		},
		// --- Subject ---
		{
			id: "SUBJECT_ALL_CAPS", score: 1.2,
			description: "Subject is predominantly uppercase letters",
			fn:          subjectAllCaps,
		},
		{
			id: "SUBJECT_EXCESSIVE_PUNCTUATION", score: 1.5,
			description: "Subject contains runs of repeated punctuation (!!!, ???, $$$)",
			fn:          func(m *message) bool { return repeatedPunctuationRE.MatchString(m.subject) },
		},
		{
			id: "SUBJECT_SPAM_PHRASE", score: 2.5,
			description: "Subject contains common spam phrases",
			fn:          func(m *message) bool { return spamPhraseRE.MatchString(m.subject) },
		},
		// --- Body & links ---
		{
			id: "BODY_SPAM_PHRASE", score: 1.5,
			description: "Message body contains common spam phrases",
			fn:          func(m *message) bool { return len(distinctPhraseHits(m.body())) >= 1 },
		},
		{
			id: "BODY_SPAM_PHRASES_MANY", score: 2.0,
			description: "Message body contains multiple distinct spam phrases",
			fn:          func(m *message) bool { return len(distinctPhraseHits(m.body())) >= 3 },
		},
		{
			id: "BODY_EXCESSIVE_URLS", score: 1.5,
			description: "Message body contains more than 10 links",
			fn:          func(m *message) bool { return len(m.links) > 10 },
		},
		{
			id: "URL_RAW_IP", score: 1.5,
			description: "Message links to a raw IP address instead of a domain name",
			fn:          linkUsesRawIP,
		},
		{
			id: "URL_SHORTENER", score: 1.0,
			description: "Message uses a known URL shortening service",
			fn:          linkUsesShortener,
		},
		{
			id: "LINK_DOMAIN_MISMATCH", score: 5.0,
			description: "Visible link text URL domain differs from the actual link target",
			fn:          linkDomainMismatch,
		},
		// --- Structure / phishing ---
		{
			id: "HTML_FORM", score: 2.5,
			description: "HTML body contains a form (common in phishing messages)",
			fn:          func(m *message) bool { return htmlFormRE.MatchString(m.html) },
		},
		{
			id: "HTML_PASSWORD_INPUT", score: 5.0,
			description: "HTML body contains a password input (common in phishing messages)",
			fn:          func(m *message) bool { return htmlPasswordRE.MatchString(m.html) },
		},
		{
			id: "HTML_NO_TEXT_ALTERNATIVE", score: 0.5,
			description: "HTML message has no plain-text alternative part",
			fn:          func(m *message) bool { return m.html != "" && strings.TrimSpace(m.text) == "" },
		},
		// --- Attachments ---
		{
			id: "ATTACHMENT_EXECUTABLE", score: 5.0,
			description: "Message has an executable attachment",
			fn:          attachmentExecutable,
		},
		{
			id: "ATTACHMENT_DOUBLE_EXTENSION", score: 2.0,
			description: "Attachment uses a double extension (e.g. invoice.pdf.exe)",
			fn:          attachmentDoubleExtension,
		},
	}

	rules := make([]matcherRule, 0, len(defs))
	for _, d := range defs {
		d := d
		rules = append(rules, matcherRule{
			id:          d.id,
			description: d.description,
			score:       d.score,
			builtin:     true,
			fn:          d.fn,
		})
	}

	return rules
}

// forgedFromDisplayName reports whether the From display name embeds an email
// address whose domain differs from the actual sender domain.
func forgedFromDisplayName(m *message) bool {
	if m.fromName == "" || m.fromDomain == "" {
		return false
	}
	for _, embedded := range emailRE.FindAllString(m.fromName, -1) {
		dom := emailDomain(embedded)
		if dom != "" && dom != m.fromDomain {
			return true
		}
	}
	return false
}

// replyToDomainMismatch reports whether the first Reply-To address uses a
// different domain than the From address.
func replyToDomainMismatch(m *message) bool {
	if m.fromDomain == "" || len(m.replyTo) == 0 || m.replyTo[0] == nil {
		return false
	}
	replyDom := emailDomain(strings.ToLower(m.replyTo[0].Address))
	return replyDom != "" && replyDom != m.fromDomain
}

// xSpamFlagSet reports whether an upstream filter already marked the message
// as spam via X-Spam-Flag / X-Spam-Status headers.
func xSpamFlagSet(m *message) bool {
	if strings.EqualFold(strings.TrimSpace(m.header("X-Spam-Flag")), "yes") {
		return true
	}
	status := strings.ToLower(strings.TrimSpace(m.header("X-Spam-Status")))
	return strings.HasPrefix(status, "yes")
}

// subjectAllCaps reports whether the subject is mostly uppercase (>=70% of
// letters) and long enough for the ratio to be meaningful.
func subjectAllCaps(m *message) bool {
	letters, upper := 0, 0
	for _, r := range m.subject {
		if unicode.IsLetter(r) {
			letters++
			if unicode.IsUpper(r) {
				upper++
			}
		}
	}
	return letters >= 8 && float64(upper)/float64(letters) >= 0.7
}

// distinctPhraseHits returns the de-duplicated spam phrases found in content.
func distinctPhraseHits(content string) []string {
	seen := map[string]bool{}
	hits := []string{}
	for _, h := range spamPhraseRE.FindAllString(content, -1) {
		key := strings.ToLower(strings.TrimSpace(h))
		if !seen[key] {
			seen[key] = true
			hits = append(hits, key)
		}
	}
	return hits
}

// linkUsesRawIP reports whether any link targets a raw IP address.
func linkUsesRawIP(m *message) bool {
	for _, l := range m.links {
		if host := linkDomain(l.href); host != "" && net.ParseIP(host) != nil {
			return true
		}
	}
	return false
}

// linkUsesShortener reports whether any link targets a known shortener.
func linkUsesShortener(m *message) bool {
	for _, l := range m.links {
		if urlShorteners[linkDomain(l.href)] {
			return true
		}
	}
	return false
}

// linkDomainMismatch reports whether an anchor's visible text contains a URL
// whose domain differs from the actual href domain (link masquerading).
func linkDomainMismatch(m *message) bool {
	for _, l := range m.links {
		if l.text == "" {
			continue
		}
		hrefDom := linkDomain(l.href)
		if hrefDom == "" {
			continue
		}
		for _, textURL := range rawURLRE.FindAllString(l.text, -1) {
			textDom := linkDomain(textURL)
			if textDom != "" && textDom != hrefDom {
				return true
			}
		}
	}
	return false
}

// attachmentExecutable reports whether any attachment has an executable
// extension.
func attachmentExecutable(m *message) bool {
	for _, name := range m.attachments {
		if executableExtensions[strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")] {
			return true
		}
	}
	return false
}

// attachmentDoubleExtension reports whether any attachment filename ends with
// a benign extension followed by an executable one.
func attachmentDoubleExtension(m *message) bool {
	for _, name := range m.attachments {
		if doubleExtRE.MatchString(name) {
			return true
		}
	}
	return false
}
