package assess

import (
	"testing"
	"time"

	"github.com/nozo-moto/dephealth/internal/depsdev"
	"github.com/nozo-moto/dephealth/internal/license"
	"github.com/nozo-moto/dephealth/internal/model"
)

func opt() Options {
	return Options{
		MinScore:      5,
		MinMaintained: 5,
		StaleDays:     365,
		License:       license.Policy{Enabled: true, Weak: "warn"},
	}
}

func score(v float64) *float64 { return &v }

func TestSupplyChainAndLicense(t *testing.T) {
	published := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	latest := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	res := Evaluate(Input{
		Dep: model.Dep{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0", Direct: true, Manifest: "package.json"},
		Version: &depsdev.Version{
			Version:     "1.0.0",
			PublishedAt: published,
			Licenses:    []string{"MIT OR GPL-3.0-only"},
			Advisories:  []string{"GHSA-xxxx"},
		},
		Package: &depsdev.Package{DefaultVersion: "2.0.0", DefaultPublished: latest},
		Project: &depsdev.Project{
			ID:      "github.com/example/left-pad",
			License: "MIT",
			Score:   score(3),
			Checks: map[string]depsdev.Check{
				"Maintained":         {Score: 0, Reason: "repo is archived"},
				"Dangerous-Workflow": {Score: 0, Reason: "untrusted checkout"},
				"Token-Permissions":  {Score: 0, Reason: "write token"},
				"Binary-Artifacts":   {Score: 10, Reason: "none"},
				"Signed-Releases":    {Score: 0, Reason: "unsigned"},
			},
		},
		Repository: "github.com/example/left-pad",
		Provenance: "UNVERIFIED_METADATA",
	}, opt())

	codes := map[string]model.Severity{}
	for _, f := range res.Findings {
		codes[f.Code] = f.Severity
	}
	if codes[model.CodeAdvisory] != model.SevHigh {
		t.Fatalf("advisory: %v", codes)
	}
	if codes[model.CodeUnmaintained] != model.SevHigh {
		t.Fatalf("unmaintained: %v", codes)
	}
	if codes[model.CodeDangerousWorkflow] != model.SevHigh {
		t.Fatalf("workflow: %v", codes)
	}
	if _, ok := codes["token-permissions"]; ok {
		t.Fatal("token permissions should not be a per-package finding")
	}
	if codes[model.CodeLicense] != 0 {
		t.Fatalf("MIT OR GPL should be choosable, got %v %s", codes[model.CodeLicense], res.LicenseSummary)
	}
	if codes[model.CodeStale] != model.SevMedium {
		t.Fatalf("stale: %v", codes)
	}
	if codes[model.CodeLowScore] != model.SevMedium {
		t.Fatalf("score: %v", codes)
	}
}

func TestCopyleftAndMissingRepo(t *testing.T) {
	res := Evaluate(Input{
		Dep:     model.Dep{Ecosystem: "pypi", Name: "x", Version: "1.2.3"},
		Version: &depsdev.Version{Version: "1.2.3", Licenses: []string{"GPL-3.0-only"}},
	}, opt())
	if res.MaxSeverity() < model.SevMedium {
		t.Fatalf("expected medium+, %#v", res.Findings)
	}
	found := false
	for _, f := range res.Findings {
		if f.Code == model.CodeLicense {
			found = true
		}
		if f.Code == model.CodeNoRepo && f.Severity != model.SevMedium {
			t.Fatalf("no repo sev %v", f.Severity)
		}
	}
	if !found {
		t.Fatal("missing license finding")
	}
}

func TestUnpinned(t *testing.T) {
	res := Evaluate(Input{Dep: model.Dep{Ecosystem: "npm", Name: "react"}}, opt())
	if len(res.Findings) != 1 || res.Findings[0].Code != model.CodeUnpinned {
		t.Fatalf("%#v", res.Findings)
	}
}
