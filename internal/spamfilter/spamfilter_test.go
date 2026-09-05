package spamfilter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resetFilter restores default state after tests that mutate global config.
func resetFilter(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		_ = LoadConfig("")
		Enabled = true
	})
}

func loadConfig(t *testing.T, yaml string) {
	t.Helper()
	resetFilter(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "spamfilter.yml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %s", err)
	}
	if err := LoadConfig(path); err != nil {
		t.Fatalf("LoadConfig: %s", err)
	}
}

// hamEmail is a well-formed transactional message expected to score low.
const hamEmail = `From: "Acme Notifications" <no-reply@example.com>
To: customer@example.com
Reply-To: support@example.com
Date: Fri, 05 Sep 2026 12:00:00 +0000
Message-ID: <202609051200.abcd@example.com>
Subject: Your monthly invoice is ready
Content-Type: multipart/alternative; boundary="ALT"

--ALT
Content-Type: text/plain; charset=utf-8

Hello,

Your monthly invoice from Acme is now available. You can view it in your
account at any time. Thank you for your business.

The Acme team
--ALT
Content-Type: text/html; charset=utf-8

<html><body><p>Hello,</p><p>Your monthly invoice from Acme is now available.</p>
<p><a href="https://example.com/account">View your account</a></p></body></html>
--ALT--
`

// phishEmail is a forged, phishy message expected to score well over 5.
const phishEmail = `From: "service@paypal.com" <security@evilish.example>
To: victim@example.com
Reply-To: refund@different-domain.example
Date: Fri, 05 Sep 2026 12:00:00 +0000
Message-ID: <x@evilish.example>
Subject: YOU HAVE WON A FREE VIAGRA LOTTERY!!! ACT NOW
Content-Type: text/html; charset=utf-8

<html><body>
<h1>Congratulations winner!</h1>
<form action="http://phish.example/collect" method="post">
<input type="text" name="user"><input type="password" name="pass">
<button type="submit">Claim prize</button>
</form>
<p>Buy cheap meds and lose weight fast with our guaranteed returns investment plan.</p>
<p><a href="http://192.168.1.50/collect">http://bit.ly/win-prize</a></p>
</body></html>
`

// executableAttachmentEmail carries a .exe attachment.
const executableAttachmentEmail = `From: sender@example.com
To: recipient@example.com
Date: Fri, 05 Sep 2026 12:00:00 +0000
Message-ID: <att@example.com>
Subject: Document for you
Content-Type: multipart/mixed; boundary="MIX"

--MIX
Content-Type: text/plain; charset=utf-8

Please see the attached document.
--MIX
Content-Type: application/octet-stream; name="invoice.exe"
Content-Disposition: attachment; filename="invoice.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALg==
--MIX--
`

func ruleNames(res Result) map[string]bool {
	names := map[string]bool{}
	for _, r := range res.Rules {
		names[r.Name] = true
	}
	return names
}

func TestCheckHamMessage(t *testing.T) {
	resetFilter(t)

	res, err := Check([]byte(hamEmail))
	if err != nil {
		t.Fatalf("Check returned error: %s", err)
	}
	if res.IsSpam {
		t.Errorf("ham message flagged as spam: score %.1f rules %v", res.Score, res.Rules)
	}
	if res.Score >= res.Threshold {
		t.Errorf("ham score %.1f reached threshold %.1f", res.Score, res.Threshold)
	}
	if res.Threshold != 5.0 {
		t.Errorf("expected default threshold 5.0, got %.1f", res.Threshold)
	}
}

func TestCheckPhishingMessage(t *testing.T) {
	resetFilter(t)

	res, err := Check([]byte(phishEmail))
	if err != nil {
		t.Fatalf("Check returned error: %s", err)
	}
	if !res.IsSpam || res.Score < 5.0 {
		t.Errorf("phishing message not flagged: IsSpam=%v score=%.1f rules=%v", res.IsSpam, res.Score, res.Rules)
	}

	names := ruleNames(res)
	for _, expected := range []string{
		"FORGED_FROM_DISPLAY_NAME",
		"REPLYTO_DOMAIN_MISMATCH",
		"SUBJECT_ALL_CAPS",
		"SUBJECT_EXCESSIVE_PUNCTUATION",
		"SUBJECT_SPAM_PHRASE",
		"HTML_FORM",
		"HTML_PASSWORD_INPUT",
		"URL_RAW_IP",
		"URL_SHORTENER",
		"LINK_DOMAIN_MISMATCH",
	} {
		if !names[expected] {
			t.Errorf("expected rule %s to trigger, got rules: %v", expected, names)
		}
	}
}

func TestExecutableAndDoubleExtension(t *testing.T) {
	resetFilter(t)

	res, err := Check([]byte(executableAttachmentEmail))
	if err != nil {
		t.Fatalf("Check returned error: %s", err)
	}
	if !ruleNames(res)["ATTACHMENT_EXECUTABLE"] {
		t.Errorf("expected ATTACHMENT_EXECUTABLE, got %v", ruleNames(res))
	}
	if !res.IsSpam {
		t.Errorf("message with .exe attachment should be spam, score %.1f", res.Score)
	}

	m := &message{
		attachments: []string{"report.pdf.exe", "normal.pdf", "photo.jpg.scr"},
		links:       []link{},
		getHeader:   func(string) string { return "" },
	}
	if !attachmentDoubleExtension(m) {
		t.Error("expected ATTACHMENT_DOUBLE_EXTENSION to match report.pdf.exe / photo.jpg.scr")
	}
}

// TestSingleSignals verifies that strong phishing signals alone reach the
// threshold on otherwise well-formed messages.
func TestSingleSignals(t *testing.T) {
	resetFilter(t)

	// only a masqueraded link (AC-2c): headers valid, text alternative present
	linkMasquerade := strings.ReplaceAll(hamEmail,
		`href="https://example.com/account">View your account<`,
		`href="https://evil-track.example/login">https://chase.com/security<`)
	res, err := Check([]byte(linkMasquerade))
	if err != nil {
		t.Fatalf("Check returned error: %s", err)
	}
	if !ruleNames(res)["LINK_DOMAIN_MISMATCH"] {
		t.Errorf("expected LINK_DOMAIN_MISMATCH, got %v", ruleNames(res))
	}
	if !res.IsSpam {
		t.Errorf("masqueraded link alone should flag spam, score %.1f", res.Score)
	}

	// only a password input
	passwordInput := strings.ReplaceAll(hamEmail,
		"<p>Hello,</p>",
		`<form action="https://example.com/update"><input type="password" name="pw"></form>`)
	res, err = Check([]byte(passwordInput))
	if err != nil {
		t.Fatalf("Check returned error: %s", err)
	}
	if !res.IsSpam {
		t.Errorf("password input alone should flag spam, score %.1f rules %v", res.Score, ruleNames(res))
	}
}

func TestUpstreamSpamFlag(t *testing.T) {
	resetFilter(t)

	email := strings.ReplaceAll(hamEmail,
		"Message-ID: <202609051200.abcd@example.com>",
		"Message-ID: <202609051200.abcd@example.com>\r\nX-Spam-Flag: YES")

	res, err := Check([]byte(email))
	if err != nil {
		t.Fatalf("Check returned error: %s", err)
	}
	if !ruleNames(res)["X_SPAM_FLAG_SET"] {
		t.Errorf("expected X_SPAM_FLAG_SET, got %v", ruleNames(res))
	}
	if !res.IsSpam {
		t.Error("message pre-flagged as spam should be spam")
	}
}

func TestMissingHeaders(t *testing.T) {
	resetFilter(t)

	res, err := Check([]byte("Subject: hi\r\nContent-Type: text/plain\r\n\r\nbody"))
	if err != nil {
		t.Fatalf("Check returned error: %s", err)
	}
	names := ruleNames(res)
	if !names["MISSING_FROM"] || !names["MISSING_DATE"] || !names["MISSING_MESSAGE_ID"] {
		t.Errorf("expected missing header rules, got %v", names)
	}
}

func TestHTMLOnlyMessage(t *testing.T) {
	resetFilter(t)

	m := &message{
		from:       "a@example.com",
		fromDomain: "example.com",
		html:       "<html><body>hi</body></html>",
		text:       "",
		links:      []link{},
		getHeader:  func(string) string { return "x" },
	}
	if !func() bool {
		for _, r := range activeRules {
			if r.id == "HTML_NO_TEXT_ALTERNATIVE" && r.fn(m) {
				return true
			}
		}
		return false
	}() {
		t.Error("expected HTML_NO_TEXT_ALTERNATIVE on HTML-only message")
	}
}

func TestDisabledFlag(t *testing.T) {
	resetFilter(t)
	Enabled = false

	res, err := Check([]byte(phishEmail))
	if err != nil {
		t.Fatalf("Check returned error: %s", err)
	}
	if res.IsSpam || res.Score != 0 || len(res.Rules) != 0 {
		t.Errorf("disabled filter should return empty result, got %+v", res)
	}
}

func TestLoadConfigCustomRule(t *testing.T) {
	loadConfig(t, `
threshold: 5
tag: "junk"
rules:
  - name: internal-alpha
    description: Internal alpha campaign marker
    score: 6
    pattern: "internal-alpha"
    target: subject
`)

	email := strings.ReplaceAll(hamEmail, "Subject: Your monthly invoice is ready",
		"Subject: Internal-Alpha testing notes")

	res, err := Check([]byte(email))
	if err != nil {
		t.Fatalf("Check returned error: %s", err)
	}
	if !res.IsSpam {
		t.Errorf("custom rule score 6 should flag message as spam, got %.1f", res.Score)
	}
	var foundCustom bool
	for _, r := range res.Rules {
		if r.Name == "internal-alpha" {
			foundCustom = true
			if r.Builtin {
				t.Error("custom rule should have Builtin=false")
			}
		}
	}
	if !foundCustom {
		t.Errorf("custom rule not found in results: %v", res.Rules)
	}
	if Tag() != "junk" {
		t.Errorf("expected tag 'junk', got %q", Tag())
	}
	if Threshold() != 5.0 {
		t.Errorf("expected threshold 5.0, got %.1f", Threshold())
	}
}

func TestLoadConfigAllowBlockListsAndDisable(t *testing.T) {
	loadConfig(t, `
threshold: 3.0
tag: "junk"
disable:
  - HTML_FORM
allowlist:
  - trusted.example
blocklist:
  - spammer.example
rules:
  - name: mid-score
    score: 3.5
    pattern: "midscoretoken"
    target: subject
`)

	if Threshold() != 3.0 {
		t.Errorf("expected threshold 3.0, got %.1f", Threshold())
	}

	// allowlist short-circuits even for phishing content
	allowHam := strings.ReplaceAll(phishEmail, "security@evilish.example", "boss@trusted.example")
	res, err := Check([]byte(allowHam))
	if err != nil {
		t.Fatalf("Check returned error: %s", err)
	}
	if res.IsSpam || res.Score != 0 || len(res.Rules) != 0 {
		t.Errorf("allowlisted sender should score 0, got %+v", res)
	}

	// blocklist forces spam for otherwise clean mail
	blocked := strings.ReplaceAll(hamEmail, "no-reply@example.com", "info@spammer.example")
	res, err = Check([]byte(blocked))
	if err != nil {
		t.Fatalf("Check returned error: %s", err)
	}
	if !res.IsSpam || !ruleNames(res)["BLOCKLIST"] {
		t.Errorf("blocklisted sender should be spam via BLOCKLIST rule, got %+v", res)
	}

	// disabled built-in rule must not trigger
	res, err = Check([]byte(phishEmail))
	if err != nil {
		t.Fatalf("Check returned error: %s", err)
	}
	if ruleNames(res)["HTML_FORM"] {
		t.Error("HTML_FORM should be disabled by config")
	}

	// mid-score rule: 3.5 >= 3.0 threshold -> spam
	mid := strings.ReplaceAll(hamEmail, "Subject: Your monthly invoice is ready",
		"Subject: midscoretoken message")
	res, err = Check([]byte(mid))
	if err != nil {
		t.Fatalf("Check returned error: %s", err)
	}
	if !res.IsSpam {
		t.Errorf("score 3.5 with threshold 3.0 should be spam, got %.1f", res.Score)
	}
}

func TestLoadConfigHeaderRule(t *testing.T) {
	loadConfig(t, `
rules:
  - name: campaign-header
    score: 6
    pattern: "bulk-marketing"
    target: header
    header: X-Campaign
`)

	email := strings.ReplaceAll(hamEmail, "Subject: Your monthly invoice is ready",
		"Subject: Your monthly invoice is ready\r\nX-Campaign: bulk-marketing")

	res, err := Check([]byte(email))
	if err != nil {
		t.Fatalf("Check returned error: %s", err)
	}
	if !res.IsSpam || !ruleNames(res)["campaign-header"] {
		t.Errorf("header rule should trigger and flag spam, got %+v", res)
	}
}

func TestLoadConfigErrors(t *testing.T) {
	cases := map[string]string{
		"missing file":        ``,
		"invalid regex":       "rules:\n  - name: bad\n    pattern: \"[a-z\"\n    target: body\n",
		"missing name":        "rules:\n  - pattern: \"foo\"\n",
		"missing pattern":     "rules:\n  - name: x\n",
		"invalid target":      "rules:\n  - name: x\n    pattern: \"foo\"\n    target: weird\n",
		"header without name": "rules:\n  - name: x\n    pattern: \"foo\"\n    target: header\n",
	}

	for name, yamlConf := range cases {
		t.Run(name, func(t *testing.T) {
			resetFilter(t)
			path := "/does/not/exist/spamfilter.yml"
			if yamlConf != "" {
				dir := t.TempDir()
				path = filepath.Join(dir, "spamfilter.yml")
				if err := os.WriteFile(path, []byte(yamlConf), 0o600); err != nil {
					t.Fatalf("write config: %s", err)
				}
			}
			if err := LoadConfig(path); err == nil {
				t.Errorf("expected error for %s, got nil", name)
			}
		})
	}
}

func TestLoadConfigEmptyPath(t *testing.T) {
	resetFilter(t)
	if err := LoadConfig(""); err != nil {
		t.Errorf("LoadConfig with empty path should not error: %s", err)
	}
	builtIn, custom := RuleCounts()
	if builtIn == 0 || custom != 0 {
		t.Errorf("expected built-in rules and no custom rules, got %d built-in %d custom", builtIn, custom)
	}
}

func TestLargeBodyDoesNotPanic(t *testing.T) {
	resetFilter(t)

	big := strings.Repeat("a", 2*1024*1024)
	email := "From: a@example.com\r\nTo: b@example.com\r\nDate: Fri, 05 Sep 2026 12:00:00 +0000\r\n" +
		"Message-ID: <big@example.com>\r\nSubject: big\r\nContent-Type: text/plain\r\n\r\n" + big

	res, err := Check([]byte(email))
	if err != nil {
		t.Fatalf("Check returned error: %s", err)
	}
	if res.IsSpam {
		t.Errorf("large benign message should not be spam, score %.1f", res.Score)
	}
}

func TestTagAndThresholdAccessors(t *testing.T) {
	loadConfig(t, `threshold: 2.5
tag: ""
`)
	if Tag() != "" {
		t.Errorf("empty tag config should disable tagging, got %q", Tag())
	}
	if Threshold() != 2.5 {
		t.Errorf("expected threshold 2.5, got %.1f", Threshold())
	}
}
