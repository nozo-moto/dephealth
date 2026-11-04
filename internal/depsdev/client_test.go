package depsdev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSelectRepoPrefersAttested(t *testing.T) {
	raw := versionJSON{
		Related: []struct {
			ProjectKey struct {
				ID string `json:"id"`
			} `json:"projectKey"`
			Provenance string `json:"relationProvenance"`
			Type       string `json:"relationType"`
		}{
			{ProjectKey: struct {
				ID string `json:"id"`
			}{ID: "github.com/unverified/repo"}, Provenance: "UNVERIFIED_METADATA", Type: "SOURCE_REPO"},
			{ProjectKey: struct {
				ID string `json:"id"`
			}{ID: "github.com/issue/repo"}, Provenance: "UNVERIFIED_METADATA", Type: "ISSUE_TRACKER"},
			{ProjectKey: struct {
				ID string `json:"id"`
			}{ID: "github.com/origin/repo"}, Provenance: "GO_ORIGIN", Type: "SOURCE_REPO"},
		},
	}
	id, prov := selectRepo(raw)
	if id != "github.com/origin/repo" || prov != "GO_ORIGIN" {
		t.Fatalf("got %s %s", id, prov)
	}

	raw.Attestations = []struct {
		SourceRepository string `json:"sourceRepository"`
		Verified         bool   `json:"verified"`
	}{{SourceRepository: "https://github.com/slsa/repo", Verified: true}}
	id, prov = selectRepo(raw)
	if id != "github.com/slsa/repo" || prov != "SLSA_ATTESTATION" {
		t.Fatalf("attestation got %s %s", id, prov)
	}
}

func TestSelectRepoGooglesourceMirror(t *testing.T) {
	raw := versionJSON{
		Links: []struct {
			Label string `json:"label"`
			URL   string `json:"url"`
		}{{Label: "SOURCE_REPO", URL: "https://go.googlesource.com/mod"}},
	}
	id, prov := selectRepo(raw)
	if id != "github.com/golang/mod" || prov != "GO_MIRROR" {
		t.Fatalf("got %s %s", id, prov)
	}
}

func TestVersionURLKeepsSlash(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.RequestURI
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := New(srv.URL, 2)
	_, err := c.Version(context.Background(), "go", "github.com/gin-gonic/gin", "v1.9.1")
	if err != ErrNotFound {
		t.Fatalf("err %v", err)
	}
	want := "/v3/systems/go/packages/github.com%2Fgin-gonic%2Fgin/versions/v1.9.1"
	if got != want {
		t.Fatalf("request URI %s, want %s", got, want)
	}
}

func TestProjectParsesScorecard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
		  "projectKey": {"id": "github.com/gin-gonic/gin"},
		  "license": "MIT",
		  "starsCount": 10,
		  "scorecard": {
		    "date": "2026-08-24T00:00:00Z",
		    "overallScore": 6.5,
		    "checks": [
		      {"name": "Maintained", "score": 0, "reason": "archived"},
		      {"name": "Signed-Releases", "score": -1, "reason": "no releases"}
		    ]
		  }
		}`))
	}))
	defer srv.Close()
	c := New(srv.URL, 2)
	p, err := c.Project(context.Background(), "github.com/gin-gonic/gin")
	if err != nil {
		t.Fatal(err)
	}
	if p.Score == nil || *p.Score != 6.5 {
		t.Fatalf("score %#v", p.Score)
	}
	if _, ok := p.Checks["Signed-Releases"]; ok {
		t.Fatal("negative score should be omitted")
	}
	if p.Checks["Maintained"].Score != 0 || p.Checks["Maintained"].Reason != "archived" {
		t.Fatalf("maintained %#v", p.Checks["Maintained"])
	}
}
