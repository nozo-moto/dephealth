package repo

import "testing"

func TestProjectID(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"https://github.com/gin-gonic/gin", "github.com/gin-gonic/gin"},
		{"https://github.com/gin-gonic/gin.git", "github.com/gin-gonic/gin"},
		{"git+https://github.com/gin-gonic/gin.git", "github.com/gin-gonic/gin"},
		{"https://github.com/gin-gonic/gin/tree/master/pkg", "github.com/gin-gonic/gin"},
		{"git@github.com:gin-gonic/gin.git", "github.com/gin-gonic/gin"},
		{"github.com/gin-gonic/gin/v2", "github.com/gin-gonic/gin"},
		{"github:gin-gonic/gin#v1.9.1", "github.com/gin-gonic/gin"},
		{"https://gitlab.com/group/sub/repo/-/tree/main", "gitlab.com/group/sub/repo"},
		{"https://bitbucket.org/org/repo", "bitbucket.org/org/repo"},
		{"golang.org/x/mod", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := ProjectID(tc.in); got != tc.want {
			t.Errorf("ProjectID(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestInferGo(t *testing.T) {
	cases := []struct{ in, id, kind string }{
		{"github.com/gin-gonic/gin/v2", "github.com/gin-gonic/gin", "INFERRED"},
		{"golang.org/x/mod", "github.com/golang/mod", "GO_MIRROR"},
		{"golang.org/x/mod/modfile", "github.com/golang/mod", "GO_MIRROR"},
		{"gopkg.in/yaml.v3", "github.com/go-yaml/yaml", "INFERRED"},
		{"gopkg.in/inconshreveable/log15.v2", "github.com/inconshreveable/log15", "INFERRED"},
		{"example.com/app", "", ""},
	}
	for _, tc := range cases {
		id, kind := InferGo(tc.in)
		if id != tc.id || kind != tc.kind {
			t.Errorf("InferGo(%q)=%s %s, want %s %s", tc.in, id, kind, tc.id, tc.kind)
		}
	}
	if got := GooglesourceMirror("https://go.googlesource.com/mod"); got != "github.com/golang/mod" {
		t.Fatalf("mirror %s", got)
	}
}
