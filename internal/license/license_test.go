package license

import (
	"strings"
	"testing"

	"github.com/nozo-moto/dephealth/internal/model"
)

func pol() Policy {
	return Policy{Enabled: true, Allow: map[string]bool{}, Deny: map[string]bool{}, Weak: "warn"}
}

func TestJudge(t *testing.T) {
	p := pol()
	cases := []struct {
		in   []string
		sev  model.Severity
		part string
	}{
		{[]string{"MIT"}, model.SevNone, "MIT"},
		{[]string{"MIT OR Apache-2.0"}, model.SevNone, "MIT"},
		{[]string{"GPL-3.0-only"}, model.SevMedium, "強いコピーレフト"},
		{[]string{"MIT OR GPL-3.0-only"}, model.SevNone, "代替として"},
		{[]string{"MIT AND GPL-3.0-only"}, model.SevMedium, "強いコピーレフト"},
		{[]string{"GPL-2.0-only WITH Classpath-exception-2.0"}, model.SevLow, "リンク例外"},
		{[]string{"MPL-2.0"}, model.SevLow, "弱いコピーレフト"},
		{[]string{"LGPL-3.0-or-later"}, model.SevLow, "弱いコピーレフト"},
		{[]string{"non-standard"}, model.SevHigh, "標準的な SPDX ではない"},
		{[]string{}, model.SevHigh, "未記載"},
		{[]string{"BUSL-1.1"}, model.SevHigh, "ソース利用に制限"},
		{[]string{"LicenseRef-Custom"}, model.SevMedium, "分類できない"},
		{[]string{"(MIT OR Apache-2.0) AND GPL-3.0-only"}, model.SevMedium, "強いコピーレフト"},
		{[]string{"MIT", "Apache-2.0"}, model.SevNone, "MIT AND Apache-2.0"},
		{[]string{"MIT", "GPL-3.0-only"}, model.SevMedium, "強いコピーレフト"},
	}
	for _, tc := range cases {
		v := Judge(tc.in, p)
		if v.Severity != tc.sev || !contains(v.Summary, tc.part) {
			t.Errorf("Judge(%q) sev=%v summary=%q, want sev=%v containing %q", tc.in, v.Severity, v.Summary, tc.sev, tc.part)
		}
	}
}

func TestAllowDeny(t *testing.T) {
	p := pol()
	p.Allow = ParseList("GPL-3.0-only")
	v := Judge([]string{"GPL-3.0-or-later"}, p)
	if v.Severity != model.SevNone {
		t.Fatalf("allow GPL family: %+v", v)
	}
	p = pol()
	p.Deny = ParseList("MIT")
	v = Judge([]string{"MIT"}, p)
	if v.Severity != model.SevHigh || !contains(v.Summary, "拒否リスト") {
		t.Fatalf("deny MIT: %+v", v)
	}
}

func TestWeakIgnore(t *testing.T) {
	p := pol()
	p.Weak = "ignore"
	v := Judge([]string{"MPL-2.0"}, p)
	if v.Severity != model.SevNone {
		t.Fatalf("weak ignore: %+v", v)
	}
}

func TestNormalizeHost(t *testing.T) {
	if got := NormalizeHost("MIT License"); got != "MIT" {
		t.Fatalf("got %q", got)
	}
	if got := NormalizeHost("Apache License 2.0"); got != "Apache-2.0" {
		t.Fatalf("got %q", got)
	}
	if got := NormalizeHost("something unknown"); got != "" {
		t.Fatalf("got %q", got)
	}
	if got := NormalizeHost("GPL-3.0-only"); got != "GPL-3.0-only" {
		t.Fatalf("got %q", got)
	}
}

func contains(s, part string) bool {
	return strings.Contains(s, part)
}
