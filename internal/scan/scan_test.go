package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/nozo-moto/dephealth/internal/assess"
	"github.com/nozo-moto/dephealth/internal/license"
	"github.com/nozo-moto/dephealth/internal/model"
)

func TestScanUsesDepsDev(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(`module example.com/app

go 1.22

require github.com/gin-gonic/gin v1.9.1
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"dependencies":{"left-pad":"1.0.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.RequestURI {
		case "/v3/systems/go/packages/github.com%2Fgin-gonic%2Fgin/versions/v1.9.1":
			_, _ = w.Write([]byte(`{
			  "versionKey": {"system":"GO","name":"github.com/gin-gonic/gin","version":"v1.9.1"},
			  "publishedAt": "2024-01-01T00:00:00Z",
			  "licenses": ["MIT"],
			  "relatedProjects": [{"projectKey":{"id":"github.com/gin-gonic/gin"},"relationType":"SOURCE_REPO","relationProvenance":"GO_ORIGIN"}]
			}`))
		case "/v3/systems/go/packages/github.com%2Fgin-gonic%2Fgin":
			_, _ = w.Write([]byte(`{"versions":[{"versionKey":{"version":"v1.9.1"},"publishedAt":"2024-01-01T00:00:00Z","isDefault":true}]}`))
		case "/v3/systems/npm/packages/left-pad/versions/1.0.0":
			_, _ = w.Write([]byte(`{
			  "versionKey": {"system":"NPM","name":"left-pad","version":"1.0.0"},
			  "publishedAt": "2016-01-01T00:00:00Z",
			  "licenses": ["GPL-3.0-only"],
			  "advisoryKeys": [{"id":"GHSA-test"}],
			  "relatedProjects": [{"projectKey":{"id":"github.com/example/left-pad"},"relationType":"SOURCE_REPO","relationProvenance":"UNVERIFIED_METADATA"}]
			}`))
		case "/v3/systems/npm/packages/left-pad":
			_, _ = w.Write([]byte(`{"versions":[{"versionKey":{"version":"1.3.0"},"publishedAt":"2024-06-01T00:00:00Z","isDefault":true}]}`))
		case "/v3/projects/github.com%2Fgin-gonic%2Fgin":
			_, _ = w.Write([]byte(`{
			  "projectKey":{"id":"github.com/gin-gonic/gin"},
			  "license":"MIT","starsCount":10,
			  "scorecard":{"date":"2026-08-01T00:00:00Z","overallScore":8,"checks":[
			    {"name":"Maintained","score":10,"reason":"active"},
			    {"name":"Dangerous-Workflow","score":10,"reason":"none"},
			    {"name":"Token-Permissions","score":0,"reason":"write"}
			  ]}
			}`))
		case "/v3/projects/github.com%2Fexample%2Fleft-pad":
			_, _ = w.Write([]byte(`{
			  "projectKey":{"id":"github.com/example/left-pad"},
			  "license":"GPL-3.0-only","starsCount":1,
			  "scorecard":{"date":"2026-08-01T00:00:00Z","overallScore":2,"checks":[
			    {"name":"Maintained","score":0,"reason":"archived"},
			    {"name":"Dangerous-Workflow","score":0,"reason":"script injection"}
			  ]}
			}`))
		default:
			t.Errorf("unexpected %s", r.RequestURI)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	rep, err := Run(context.Background(), []string{dir}, Option{
		Concurrency: 4,
		DepsDevURL:  srv.URL,
		Assess: assess.Options{
			MinScore:      5,
			MinMaintained: 5,
			StaleDays:     365,
			License:       license.Policy{Enabled: true, Weak: "warn"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 2 {
		t.Fatalf("results %d", len(rep.Results))
	}
	var gin, left model.Result
	for _, r := range rep.Results {
		switch r.Name {
		case "github.com/gin-gonic/gin":
			gin = r
		case "left-pad":
			left = r
		}
	}
	if gin.Repository != "github.com/gin-gonic/gin" || gin.Provenance != "GO_ORIGIN" || gin.LicenseSummary != "MIT" {
		t.Fatalf("gin %+v", gin)
	}
	if gin.MaxSeverity() >= model.SevMedium {
		t.Fatalf("gin should be clean, %#v", gin.Findings)
	}
	if left.MaxSeverity() != model.SevHigh {
		t.Fatalf("left-pad %#v", left.Findings)
	}
	codes := map[string]bool{}
	for _, f := range left.Findings {
		codes[f.Code] = true
	}
	for _, code := range []string{model.CodeAdvisory, model.CodeUnmaintained, model.CodeDangerousWorkflow, model.CodeLicense, model.CodeStale} {
		if !codes[code] {
			t.Errorf("missing %s in %#v", code, left.Findings)
		}
	}
}
