package manifest

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nozo-moto/dephealth/internal/model"
)

var skipDir = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true,
	"target": true, ".venv": true, "venv": true, "third_party": true, ".terraform": true,
	"site-packages": true, "__pycache__": true,
	// git の linked worktree の標準的な置き場。
	".worktrees": true,
}

// ignorer は --ignore のパターンを保持する。
// パターンは root からの相対パス、またはパスの 1 区間に対する glob として効く。
type ignorer struct {
	patterns []string
}

func newIgnorer(patterns []string) ignorer {
	var out []string
	for _, p := range patterns {
		for _, piece := range strings.Split(p, ",") {
			piece = strings.TrimSpace(filepath.ToSlash(piece))
			if piece != "" {
				out = append(out, piece)
			}
		}
	}
	return ignorer{patterns: out}
}

func (ig ignorer) match(rel string) bool {
	if len(ig.patterns) == 0 {
		return false
	}
	rel = filepath.ToSlash(rel)
	if rel == "." || rel == "" {
		return false
	}
	for _, p := range ig.patterns {
		if ok, _ := path.Match(p, rel); ok {
			return true
		}
		for _, seg := range strings.Split(rel, "/") {
			if ok, _ := path.Match(p, seg); ok {
				return true
			}
		}
	}
	return false
}

// Discover は roots 以下の依存マニフェストを読む。
// directOnly のとき、直接依存だけを返す。区別できない場合は全部を返し、warning を付ける。
// ignore は root からの相対パスまたは区間名の glob パターン。
func Discover(roots []string, directOnly bool, ignore []string) (deps []model.Dep, manifests int, warnings []string, err error) {
	if len(roots) == 0 {
		roots = []string{"."}
	}
	ig := newIgnorer(ignore)
	seen := map[string]bool{}
	for _, root := range roots {
		root = filepath.Clean(root)
		info, statErr := os.Stat(root)
		if statErr != nil {
			return nil, manifests, warnings, fmt.Errorf("%s を読めません: %w", root, statErr)
		}
		if !info.IsDir() {
			n, w := collectFile(root, seen, &deps)
			manifests += n
			warnings = append(warnings, w...)
			continue
		}
		walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				warnings = append(warnings, walkErr.Error())
				return nil
			}
			if d.IsDir() {
				if p == root {
					return nil
				}
				rel, relErr := filepath.Rel(root, p)
				if relErr != nil {
					rel = d.Name()
				}
				if skipDir[d.Name()] || ig.match(rel) {
					return fs.SkipDir
				}
				return nil
			}
			rel, relErr := filepath.Rel(root, p)
			if relErr == nil && ig.match(rel) {
				return nil
			}
			n, w := collectFile(p, seen, &deps)
			manifests += n
			warnings = append(warnings, w...)
			return nil
		})
		if walkErr != nil {
			return nil, manifests, warnings, walkErr
		}
	}
	deps = dedupe(deps)
	if directOnly {
		var direct []model.Dep
		for _, d := range deps {
			if d.Direct {
				direct = append(direct, d)
			}
		}
		if len(direct) == 0 && len(deps) > 0 {
			warnings = append(warnings, "直接依存を区別できなかったため、見つかった依存をすべて評価します")
		} else {
			deps = direct
		}
	}
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Ecosystem != deps[j].Ecosystem {
			return deps[i].Ecosystem < deps[j].Ecosystem
		}
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})
	return deps, manifests, warnings, nil
}

func collectFile(path string, seen map[string]bool, deps *[]model.Dep) (int, []string) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	var (
		found []model.Dep
		err   error
		key   string
		count int
	)
	switch base {
	case "go.mod":
		key = "go:" + path
		if seen[key] {
			return 0, nil
		}
		seen[key] = true
		count = 1
		b, rerr := readFile(path)
		if rerr != nil {
			return count, []string{rerr.Error()}
		}
		found, err = parseGoMod(path, b)
	case "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock":
		key = "node:" + dir
		if seen[key] {
			return 0, nil
		}
		seen[key] = true
		count = 1
		found, err = parseNodeDir(dir)
	case "Cargo.toml", "Cargo.lock":
		key = "cargo:" + dir
		if seen[key] {
			return 0, nil
		}
		seen[key] = true
		count = 1
		found, err = parseCargoDir(dir)
	case "pyproject.toml", "requirements.txt", "poetry.lock", "uv.lock":
		key = "py:" + dir
		if seen[key] {
			return 0, nil
		}
		seen[key] = true
		count = 1
		found, err = parsePythonDir(dir)
	case "Gemfile", "Gemfile.lock":
		key = "gem:" + dir
		if seen[key] {
			return 0, nil
		}
		seen[key] = true
		count = 1
		found, err = parseGemDir(dir)
	default:
		return 0, nil
	}
	if err != nil {
		return count, []string{fmt.Sprintf("%s: %s", path, err.Error())}
	}
	*deps = append(*deps, found...)
	return count, nil
}

func dedupe(in []model.Dep) []model.Dep {
	type key struct{ eco, name, ver string }
	order := []key{}
	by := map[key]model.Dep{}
	for _, d := range in {
		name := d.Name
		if d.Ecosystem == "pypi" {
			name = normPy(name)
		}
		k := key{d.Ecosystem, name, d.Version}
		prev, ok := by[k]
		if !ok {
			order = append(order, k)
			prev = d
			prev.Manifest = ""
		}
		if d.Direct {
			prev.Direct = true
		}
		if d.Direct && !d.Dev {
			prev.Dev = false
		} else if !prev.Direct {
			prev.Dev = prev.Dev || d.Dev
		}
		if !d.SkipRegistry {
			prev.SkipRegistry = false
		}
		if prev.RepoHint == "" {
			prev.RepoHint = d.RepoHint
		}
		if d.Manifest != "" && !strings.Contains(prev.Manifest, d.Manifest) {
			if prev.Manifest != "" {
				prev.Manifest += "\n"
			}
			prev.Manifest += d.Manifest
		}
		by[k] = prev
	}
	out := make([]model.Dep, 0, len(order))
	for _, k := range order {
		out = append(out, by[k])
	}
	return out
}
