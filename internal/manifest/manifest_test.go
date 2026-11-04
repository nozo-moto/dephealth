package manifest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nozo-moto/dephealth/internal/model"
)

func TestGoModReplaceAndIndirect(t *testing.T) {
	dir := t.TempDir()
	body := []byte(`module example.com/app

go 1.22

require (
    github.com/gin-gonic/gin v1.9.1
    example.com/local v1.0.0
    golang.org/x/mod v0.20.0 // indirect
)

replace github.com/gin-gonic/gin => github.com/gin-gonic/gin v1.9.0
replace example.com/local => ./local
`)
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	deps, n, warns, err := Discover([]string{dir}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(warns) != 0 {
		t.Fatalf("manifests %d warns %v", n, warns)
	}
	if len(deps) != 2 {
		t.Fatalf("deps %#v", deps)
	}
	by := map[string]string{}
	direct := map[string]bool{}
	for _, d := range deps {
		by[d.Name] = d.Version
		direct[d.Name] = d.Direct
	}
	if by["github.com/gin-gonic/gin"] != "v1.9.0" || !direct["github.com/gin-gonic/gin"] {
		t.Fatalf("gin %#v", deps)
	}
	if by["golang.org/x/mod"] != "v0.20.0" || direct["golang.org/x/mod"] {
		t.Fatalf("mod %#v", deps)
	}
}

func TestPackageLockAndExactSpec(t *testing.T) {
	if v, _, local := npmSpec("1.2.3"); v != "1.2.3" || local {
		t.Fatalf("exact %q", v)
	}
	if v, _, _ := npmSpec("^1.2.3"); v != "" {
		t.Fatalf("range should be unpinned, got %q", v)
	}
	if _, hint, _ := npmSpec("github:gin-gonic/gin#v1.9.1"); hint != "github.com/gin-gonic/gin" {
		t.Fatalf("hint %q", hint)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{
	  "dependencies": {"react": "^18.2.0", "left-pad": "1.0.0"},
	  "devDependencies": {"vitest": "^1.0.0"}
	}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {},
	    "node_modules/react": {"version": "18.2.0"},
	    "node_modules/left-pad": {"version": "1.0.0"},
	    "node_modules/vitest": {"version": "1.2.0", "dev": true},
	    "node_modules/js-tokens": {"version": "4.0.0"}
	  }
	}`), 0o644); err != nil {
		t.Fatal(err)
	}
	deps, _, _, err := Discover([]string{dir}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, d := range deps {
		got[d.Name+"@"+d.Version] = d.Direct
		if d.Name == "vitest" && !d.Dev {
			t.Fatal("vitest should be dev")
		}
	}
	if !got["react@18.2.0"] || !got["left-pad@1.0.0"] || got["js-tokens@4.0.0"] {
		t.Fatalf("direct flags %#v", deps)
	}
	directOnly, _, _, err := Discover([]string{dir}, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(directOnly) != 3 {
		t.Fatalf("direct only %#v", directOnly)
	}
}

func TestPnpmYarnCargoPythonGem(t *testing.T) {
	dir := t.TempDir()
	must := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pnpm := t.TempDir()
	mustWrite(t, filepath.Join(pnpm, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\npackages:\n  react@18.2.0:\n    resolution: {}\n  '@scope/pkg@1.2.3':\n    resolution: {}\n")
	mustWrite(t, filepath.Join(pnpm, "package.json"), `{"dependencies":{"react":"^18.0.0"}}`)
	deps, _, _, err := Discover([]string{pnpm}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !has(deps, "npm", "react", "18.2.0", true) || !has(deps, "npm", "@scope/pkg", "1.2.3", false) {
		t.Fatalf("pnpm %#v", deps)
	}

	yarn := t.TempDir()
	mustWrite(t, filepath.Join(yarn, "package.json"), `{"dependencies":{"left-pad":"^1.0.0"}}`)
	mustWrite(t, filepath.Join(yarn, "yarn.lock"), "\"left-pad@^1.0.0\":\n  version \"1.0.0\"\n")
	deps, _, _, err = Discover([]string{yarn}, false, nil)
	if err != nil || !has(deps, "npm", "left-pad", "1.0.0", true) {
		t.Fatalf("yarn %#v %v", deps, err)
	}

	cargo := t.TempDir()
	mustWrite(t, filepath.Join(cargo, "Cargo.toml"), "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\n\n[dev-dependencies]\ntokio = { version = \"1\", features = [\"rt\"] }\n")
	mustWrite(t, filepath.Join(cargo, "Cargo.lock"), "version = 3\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.210\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"tokio\"\nversion = \"1.40.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"gitdep\"\nversion = \"0.2.0\"\nsource = \"git+https://github.com/example/gitdep?rev=abc\"\n")
	deps, _, _, err = Discover([]string{cargo}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !has(deps, "cargo", "serde", "1.0.210", true) || !has(deps, "cargo", "tokio", "1.40.0", true) {
		t.Fatalf("cargo %#v", deps)
	}
	for _, d := range deps {
		if d.Name == "app" {
			t.Fatal("workspace package should be skipped")
		}
		if d.Name == "gitdep" && (d.RepoHint != "github.com/example/gitdep" || !d.SkipRegistry) {
			t.Fatalf("gitdep %#v", d)
		}
	}

	py := t.TempDir()
	mustWrite(t, filepath.Join(py, "pyproject.toml"), "[project]\nname = \"app\"\ndependencies = [\n  \"requests==2.31.0\",\n  \"flask>=2\",\n]\n")
	mustWrite(t, filepath.Join(py, "requirements.txt"), "requests==2.31.0\nflask==2.3.3\n")
	deps, _, _, err = Discover([]string{py}, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !has(deps, "pypi", "requests", "2.31.0", true) || !has(deps, "pypi", "flask", "2.3.3", true) {
		t.Fatalf("python %#v", deps)
	}

	gem := t.TempDir()
	mustWrite(t, filepath.Join(gem, "Gemfile.lock"), "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.8)\n      rack-session\n    rack-session (1.0.2)\n\nDEPENDENCIES\n  rack (~> 2.2)\n")
	deps, _, _, err = Discover([]string{gem}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !has(deps, "rubygems", "rack", "2.2.8", true) || !has(deps, "rubygems", "rack-session", "1.0.2", false) {
		t.Fatalf("gem %#v", deps)
	}
	_ = must
	_ = dir
}

func TestIgnoreWorktreesAndPatterns(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/root\n\ngo 1.22\n\nrequire github.com/root/dep v1.0.0\n")
	mustWrite(t, filepath.Join(root, ".worktrees", "feature", "go.mod"), "module example.com/wt\n\ngo 1.22\n\nrequire github.com/wt/dep v1.0.0\n")
	mustWrite(t, filepath.Join(root, "playground", "go.mod"), "module example.com/play\n\ngo 1.22\n\nrequire github.com/play/dep v1.0.0\n")
	mustWrite(t, filepath.Join(root, "docs", "sample", "go.mod"), "module example.com/docs\n\ngo 1.22\n\nrequire github.com/docs/dep v1.0.0\n")

	deps, _, _, err := Discover([]string{root}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, d := range deps {
		names[d.Name] = true
	}
	if !names["github.com/root/dep"] || !names["github.com/play/dep"] || !names["github.com/docs/dep"] {
		t.Fatalf("baseline missing deps: %v", names)
	}
	if names["github.com/wt/dep"] {
		t.Fatal(".worktrees should be ignored by default")
	}

	deps, _, _, err = Discover([]string{root}, false, []string{"playground,docs"})
	if err != nil {
		t.Fatal(err)
	}
	names = map[string]bool{}
	for _, d := range deps {
		names[d.Name] = true
	}
	if names["github.com/play/dep"] || names["github.com/docs/dep"] || !names["github.com/root/dep"] {
		t.Fatalf("custom ignore failed: %v", names)
	}

	// root 自体を .worktrees 配下で走査する場合も既定で無視されない（root は常に走査対象）。
	deps, _, _, err = Discover([]string{filepath.Join(root, ".worktrees", "feature")}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !has(deps, "go", "github.com/wt/dep", "v1.0.0", true) {
		t.Fatalf("explicit root should be scanned: %#v", deps)
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func has(deps []model.Dep, eco, name, ver string, direct bool) bool {
	for _, d := range deps {
		if d.Ecosystem == eco && d.Name == name && d.Version == ver && d.Direct == direct {
			return true
		}
	}
	return false
}
