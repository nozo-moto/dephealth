package manifest

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/nozo-moto/dephealth/internal/model"
	"github.com/nozo-moto/dephealth/internal/repo"
)

func parseNodeDir(dir string) ([]model.Dep, error) {
	manifest := filepath.Join(dir, "package.json")
	direct := map[string]kind{}
	var fallback []model.Dep
	if exists(manifest) {
		b, err := readFile(manifest)
		if err != nil {
			return nil, err
		}
		direct, fallback, err = parsePackageJSON(manifest, b)
		if err != nil {
			return nil, err
		}
	}
	var locked []model.Dep
	var err error
	switch {
	case exists(filepath.Join(dir, "package-lock.json")):
		locked, err = parseFileDeps(filepath.Join(dir, "package-lock.json"), parseNPMLock)
	case exists(filepath.Join(dir, "pnpm-lock.yaml")):
		locked, err = parseFileDeps(filepath.Join(dir, "pnpm-lock.yaml"), parsePnpmLock)
	case exists(filepath.Join(dir, "yarn.lock")):
		locked, err = parseFileDeps(filepath.Join(dir, "yarn.lock"), parseYarnLock)
	}
	if err != nil {
		return nil, err
	}
	if len(locked) == 0 {
		return fallback, nil
	}
	for i := range locked {
		if k, ok := direct[locked[i].Name]; ok {
			locked[i].Direct = true
			locked[i].Dev = k.dev && !k.prod
		}
	}
	return locked, nil
}

type kind struct {
	prod bool
	dev  bool
}

func parseFileDeps(path string, fn func(string, []byte) ([]model.Dep, error)) ([]model.Dep, error) {
	b, err := readFile(path)
	if err != nil {
		return nil, err
	}
	return fn(path, b)
}

func parsePackageJSON(manifest string, data []byte) (map[string]kind, []model.Dep, error) {
	var raw struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, err
	}
	direct := map[string]kind{}
	add := func(name, spec string, dev bool) {
		k := direct[name]
		if dev {
			k.dev = true
		} else {
			k.prod = true
		}
		direct[name] = k
	}
	var fallback []model.Dep
	consume := func(m map[string]string, dev bool) {
		for name, spec := range m {
			add(name, spec, dev)
			ver, hint, local := npmSpec(spec)
			if local {
				continue
			}
			d := model.Dep{
				Ecosystem: "npm",
				Name:      name,
				Version:   ver,
				Direct:    true,
				Dev:       dev,
				Manifest:  manifest,
				RepoHint:  hint,
			}
			if hint != "" && ver == "" {
				d.SkipRegistry = true
			}
			fallback = append(fallback, d)
		}
	}
	consume(raw.Dependencies, false)
	consume(raw.OptionalDependencies, false)
	consume(raw.DevDependencies, true)
	return direct, fallback, nil
}

func npmSpec(spec string) (version, hint string, local bool) {
	spec = strings.TrimSpace(spec)
	switch {
	case spec == "", spec == "*",
		strings.HasPrefix(spec, "workspace:"),
		strings.HasPrefix(spec, "catalog:"),
		strings.HasPrefix(spec, "file:"),
		strings.HasPrefix(spec, "link:"),
		strings.HasPrefix(spec, "portal:"):
		return "", "", true
	}
	if strings.HasPrefix(spec, "npm:") {
		spec = strings.TrimPrefix(spec, "npm:")
		if at := strings.LastIndex(spec, "@"); at > 0 {
			name := spec[:at]
			ver := spec[at+1:]
			if isExactVersion(ver) {
				return ver, "", false
			}
			_ = name
			return "", "", false
		}
	}
	if strings.Contains(spec, "://") || strings.HasPrefix(spec, "git+") || strings.HasPrefix(spec, "github:") || strings.HasPrefix(spec, "gitlab:") || strings.HasPrefix(spec, "bitbucket:") || strings.HasPrefix(spec, "git@") {
		return "", repo.ProjectID(spec), false
	}
	spec = strings.TrimPrefix(spec, "=")
	if isExactVersion(spec) {
		return strings.TrimPrefix(spec, "v"), "", false
	}
	if strings.HasPrefix(spec, "v") && isExactVersion(spec[1:]) {
		return spec[1:], "", false
	}
	return "", "", false
}

func isExactVersion(v string) bool {
	if len(v) == 0 || v[0] < '0' || v[0] > '9' {
		return false
	}
	i := 0
	for n := 0; n < 3; n++ {
		if n > 0 {
			if i >= len(v) || v[i] != '.' {
				return false
			}
			i++
		}
		start := i
		for i < len(v) && v[i] >= '0' && v[i] <= '9' {
			i++
		}
		if i == start {
			return false
		}
	}
	for ; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '.', c == '-', c == '+', c == '_':
		default:
			return false
		}
	}
	return true
}

func parseNPMLock(manifest string, data []byte) ([]model.Dep, error) {
	var raw struct {
		Packages map[string]struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			Dev      bool   `json:"dev"`
			Link     bool   `json:"link"`
			Resolved string `json:"resolved"`
		} `json:"packages"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	var out []model.Dep
	if len(raw.Packages) > 0 {
		for path, p := range raw.Packages {
			if path == "" || p.Link || p.Version == "" {
				continue
			}
			name := p.Name
			if name == "" {
				name = npmName(path)
			}
			if name == "" {
				continue
			}
			d := model.Dep{
				Ecosystem: "npm",
				Name:      name,
				Version:   p.Version,
				Dev:       p.Dev,
				Manifest:  manifest,
			}
			if hint := registryRepo(p.Resolved); hint != "" {
				d.RepoHint = hint
				d.SkipRegistry = true
			}
			out = append(out, d)
		}
		return out, nil
	}
	for name, child := range raw.Dependencies {
		walkNPMV1(name, child, manifest, &out)
	}
	return out, nil
}

func walkNPMV1(name string, raw json.RawMessage, manifest string, out *[]model.Dep) {
	var node struct {
		Version      string                     `json:"version"`
		Resolved     string                     `json:"resolved"`
		Dev          bool                       `json:"dev"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	if json.Unmarshal(raw, &node) != nil || name == "" || node.Version == "" {
		return
	}
	d := model.Dep{Ecosystem: "npm", Name: name, Version: node.Version, Dev: node.Dev, Manifest: manifest}
	if hint := registryRepo(node.Resolved); hint != "" {
		d.RepoHint = hint
		d.SkipRegistry = true
	}
	*out = append(*out, d)
	for n, child := range node.Dependencies {
		walkNPMV1(n, child, manifest, out)
	}
}

func npmName(p string) string {
	p = filepath.ToSlash(p)
	const mark = "node_modules/"
	i := strings.LastIndex(p, mark)
	if i < 0 {
		return ""
	}
	return p[i+len(mark):]
}

func registryRepo(resolved string) string {
	if resolved == "" {
		return ""
	}
	if strings.Contains(resolved, "registry.npmjs.org") ||
		strings.Contains(resolved, "registry.yarnpkg.com") ||
		strings.Contains(resolved, "npm.pkg.github.com") {
		return ""
	}
	return repo.ProjectID(resolved)
}

func parsePnpmLock(manifest string, data []byte) ([]model.Dep, error) {
	var out []model.Dep
	inPackages := false
	for _, line := range strings.Split(string(data), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "packages:" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			inPackages = true
			continue
		}
		if inPackages && line != "" && line[0] != ' ' && line[0] != '\t' && line[0] != '#' {
			break
		}
		if !inPackages || strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "\t") {
			continue
		}
		if !strings.HasPrefix(line, "  ") {
			continue
		}
		key := strings.TrimSpace(line)
		key = strings.TrimSuffix(key, ":")
		key = strings.Trim(key, `"'`)
		name, ver, ok := splitPnpmKey(key)
		if !ok {
			continue
		}
		out = append(out, model.Dep{
			Ecosystem: "npm",
			Name:      name,
			Version:   ver,
			Manifest:  manifest,
		})
	}
	return out, nil
}

func splitPnpmKey(s string) (string, string, bool) {
	s = strings.TrimPrefix(s, "/")
	if i := strings.Index(s, "("); i >= 0 {
		s = s[:i]
	}
	at := strings.LastIndex(s, "@")
	if at <= 0 {
		return "", "", false
	}
	name, ver := s[:at], s[at+1:]
	if name == "" || ver == "" || strings.Contains(ver, ":") || strings.Contains(ver, "/") {
		return "", "", false
	}
	return name, ver, true
}

func parseYarnLock(manifest string, data []byte) ([]model.Dep, error) {
	var out []model.Dep
	var names []string
	version := ""
	flush := func() {
		if version == "" {
			names = nil
			return
		}
		seen := map[string]bool{}
		for _, n := range names {
			if n == "" || seen[n] {
				continue
			}
			seen[n] = true
			out = append(out, model.Dep{Ecosystem: "npm", Name: n, Version: version, Manifest: manifest})
		}
		names = nil
		version = ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.Contains(line, "@") && strings.HasSuffix(strings.TrimSpace(line), ":") {
			flush()
			raw := strings.TrimSuffix(strings.TrimSpace(line), ":")
			for _, part := range strings.Split(raw, ",") {
				if n := yarnName(part); n != "" {
					names = append(names, n)
				}
			}
			continue
		}
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "version ") || strings.HasPrefix(trim, "version:") {
			version = yarnVersion(trim)
		}
	}
	flush()
	return out, nil
}

func yarnName(key string) string {
	key = strings.Trim(strings.TrimSpace(key), `"'`)
	at := strings.LastIndex(key, "@")
	if at <= 0 {
		return ""
	}
	return key[:at]
}

func yarnVersion(line string) string {
	rest := line
	switch {
	case strings.HasPrefix(rest, "version:"):
		rest = strings.TrimSpace(rest[len("version:"):])
	case strings.HasPrefix(rest, "version "):
		rest = strings.TrimSpace(rest[len("version "):])
	}
	rest = strings.Trim(rest, `"'`)
	if rest == "" || strings.Contains(rest, "use.local") {
		return ""
	}
	return rest
}
