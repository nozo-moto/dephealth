package ghissue

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseRef(t *testing.T) {
	r, err := ParseRef("levetty/dephealth#12")
	if err != nil || r.Owner != "levetty" || r.Repo != "dephealth" || r.Number != 12 {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = ParseRef("https://github.com/levetty/dephealth/issues/4")
	if err != nil || r.Number != 4 {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = ParseRef("https://github.com/levetty/dephealth")
	if err != nil || r.Number != 0 || r.Repo != "dephealth" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := ParseRef("nope"); err == nil {
		t.Fatal("expected error")
	}
}

func TestUpsertComment(t *testing.T) {
	var patched bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Errorf("missing auth")
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/comments"):
			_, _ = w.Write([]byte(`[{"id":9,"body":"<!-- dephealth-summary -->\nold"}]`))
		case r.Method == http.MethodPatch:
			patched = true
			var payload struct {
				Body string `json:"body"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(payload.Body, "new summary") || !strings.Contains(payload.Body, Marker) {
				t.Errorf("body %s", payload.Body)
			}
			_, _ = w.Write([]byte(`{"html_url":"https://github.com/o/r/issues/3#issuecomment-9"}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	u, err := Publish(context.Background(), srv.URL, "tok", Ref{Owner: "o", Repo: "r", Number: 3}, "", "new summary")
	if err != nil {
		t.Fatal(err)
	}
	if !patched || !strings.Contains(u, "issuecomment-9") {
		t.Fatalf("patched=%v url=%s", patched, u)
	}
}

func TestCreateIssue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method %s", r.Method)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["title"] != "t" || !strings.Contains(body["body"], Marker) {
			t.Fatalf("%v", body)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"html_url":"https://github.com/o/r/issues/1"}`))
	}))
	defer srv.Close()
	u, err := Publish(context.Background(), srv.URL, "tok", Ref{Owner: "o", Repo: "r"}, "t", "hello")
	if err != nil || u == "" {
		t.Fatalf("%s %v", u, err)
	}
}
