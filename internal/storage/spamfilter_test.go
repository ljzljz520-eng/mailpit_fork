package storage

import (
	"testing"

	"github.com/axllent/mailpit/internal/spamfilter"
)

var testSpamHamEmail = []byte(`From: "Acme Notifications" <no-reply@example.com>
To: customer@example.com
Date: Fri, 05 Sep 2026 12:00:00 +0000
Message-ID: <ham@example.com>
Subject: Your order has shipped
Content-Type: multipart/alternative; boundary="ALT"

--ALT
Content-Type: text/plain; charset=utf-8

Hello, your order has shipped and is on its way. Thank you for your business.
--ALT
Content-Type: text/html; charset=utf-8

<html><body><p>Hello, your order has shipped.</p>
<p><a href="https://example.com/track">Track your order</a></p></body></html>
--ALT--
`)

var testSpamSpamEmail = []byte(`From: "service@paypal.com" <security@evilish.example>
To: victim@example.com
Date: Fri, 05 Sep 2026 12:00:00 +0000
Message-ID: <spam@evilish.example>
Subject: YOU HAVE WON A FREE VIAGRA LOTTERY!!!
Content-Type: text/html; charset=utf-8

<html><body>
<form action="http://phish.example/collect"><input type="password" name="pass"></form>
<p>Claim your prize and buy cheap meds now.</p>
<p><a href="http://10.0.0.5/x">http://paypal.com/login</a></p>
</body></html>
`)

func hasTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

func TestSpamFilterAutoTagging(t *testing.T) {
	setup("")
	defer Close()

	if err := spamfilter.LoadConfig(""); err != nil {
		t.Fatalf("LoadConfig: %s", err)
	}
	spamfilter.Enabled = true
	t.Cleanup(func() {
		spamfilter.Enabled = true
		_ = spamfilter.LoadConfig("")
	})

	// ham message is stored without the spam tag
	hamID, err := Store(&testSpamHamEmail, nil)
	if err != nil {
		t.Fatalf("store ham: %s", err)
	}
	hamMsg, err := GetMessage(hamID)
	if err != nil {
		t.Fatalf("get ham: %s", err)
	}
	if hasTag(hamMsg.Tags, "spam") {
		t.Errorf("ham message should not be tagged spam, tags: %v", hamMsg.Tags)
	}

	// obvious spam is stored with the spam tag
	spamID, err := Store(&testSpamSpamEmail, nil)
	if err != nil {
		t.Fatalf("store spam: %s", err)
	}
	spamMsg, err := GetMessage(spamID)
	if err != nil {
		t.Fatalf("get spam: %s", err)
	}
	if !hasTag(spamMsg.Tags, "spam") {
		t.Errorf("spam message should be tagged spam, tags: %v", spamMsg.Tags)
	}

	// disabled filter must not tag
	if err := DeleteAllMessages(); err != nil {
		t.Fatalf("delete: %s", err)
	}
	spamfilter.Enabled = false
	spamID2, err := Store(&testSpamSpamEmail, nil)
	if err != nil {
		t.Fatalf("store spam (disabled): %s", err)
	}
	spamMsg2, err := GetMessage(spamID2)
	if err != nil {
		t.Fatalf("get spam (disabled): %s", err)
	}
	if hasTag(spamMsg2.Tags, "spam") {
		t.Errorf("spam message should not be tagged when filter disabled, tags: %v", spamMsg2.Tags)
	}
}
