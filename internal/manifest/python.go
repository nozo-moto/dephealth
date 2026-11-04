package manifest

import (
	"path/filepath"
	"strings"

	"github.com/nozo-moto/dephealth/internal/model"
	"github.com/nozo-moto/dephealth/internal/repo"
)

func parsePythonDir(dir string) ([]model.Dep, error) {
	var declared []model.Dep
	pyproject := filepath.Join(dir, "pyproject.toml")
	if exists(pyproject) {
		b, err := readFile(pyproject)
		if err != nil {
			return nil, err
		}
		declared = append(declared, parsePyProject(pyproject, b)...)
	}
	reqPath := filepath.Join(dir, "requirements.txt")
	var reqs []model.Dep
	if exists(reqPath) {
		b, err := readFile(reqPath)
		if err != nil {
			return nil, err
		}
		reqs = parseRequirements(reqPath, b)
	}
	var locked []model.Dep
	for _, name := range []string{"poetry.lock", "uv.lock"} {
		p := filepath.Join(dir, name)
		if !exists(p) {
			continue
		}
		b, err := readFile(p)
		if err != nil {
			return nil, err
		}
		locked = parsePythonLock(p, b)
		break
	}
	directNames := map[string]bool{}
	for _, d := range declared {
		directNames[normPy(d.Name)] = true
	}
	for _, d := range reqs {
		directNames[normPy(d.Name)] = true
	}
	if len(locked) > 0 {
		for i := range locked {
			locked[i].Direct = directNames[normPy(locked[i].Name)]
		}
		if len(directNames) == 0 {
			for i := range locked {
				locked[i].Direct = true
			}
		}
		return locked, nil
	}
	// ピンのある requirements を優先し、pyproject にしか無い名前も残す。
	byName := map[string]model.Dep{}
	var order []string
	add := func(d model.Dep) {
		k := normPy(d.Name)
		if prev, ok := byName[k]; ok {
			if prev.Version == "" && d.Version != "" {
				d.Direct = true
				d.Manifest = joinManifest(prev.Manifest, d.Manifest)
				byName[k] = d
			}
			return
		}
		order = append(order, k)
		byName[k] = d
	}
	for _, d := range declared {
		add(d)
	}
	for _, d := range reqs {
		add(d)
	}
	var out []model.Dep
	for _, k := range order {
		out = append(out, byName[k])
	}
	return out, nil
}

func joinManifest(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" || strings.Contains(a, b) {
		return a
	}
	return a + "\n" + b
}

func normPy(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	dash := false
	for _, r := range s {
		if r == '-' || r == '_' || r == '.' {
			if !dash && b.Len() > 0 {
				b.WriteByte('_')
				dash = true
			}
			continue
		}
		dash = false
		b.WriteRune(r)
	}
	return b.String()
}

func parsePyProject(manifest string, data []byte) []model.Dep {
	var out []model.Dep
	seen := map[string]bool{}
	addReq := func(req string, dev bool) {
		name, ver, hint, ok := parseReq(req)
		if !ok || seen[normPy(name)] {
			return
		}
		seen[normPy(name)] = true
		d := model.Dep{Ecosystem: "pypi", Name: name, Version: ver, Direct: true, Dev: dev, Manifest: manifest, RepoHint: hint}
		if hint != "" && ver == "" {
			d.SkipRegistry = true
		}
		out = append(out, d)
	}
	for _, sec := range splitTOML(string(data)) {
		switch {
		case sec.name == "project":
			for _, req := range arrayAfterKey(sec.lines, "dependencies") {
				addReq(req, false)
			}
		case sec.name == "project.optional-dependencies":
			for _, line := range sec.lines {
				if !bracketsBalanced(line) && !strings.Contains(line, "[") {
					continue
				}
			}
			for _, req := range quotedStrings(strings.Join(sec.lines, "\n")) {
				if looksLikeReq(req) {
					addReq(req, false)
				}
			}
		case strings.Contains(sec.name, "poetry") && strings.HasSuffix(sec.name, "dependencies"):
			dev := strings.Contains(sec.name, "dev")
			for name, value := range assignments(sec.lines) {
				if name == "python" || seen[normPy(name)] {
					continue
				}
				ver := poetryVersion(value)
				seen[normPy(name)] = true
				out = append(out, model.Dep{
					Ecosystem: "pypi",
					Name:      name,
					Version:   ver,
					Direct:    true,
					Dev:       dev,
					Manifest:  manifest,
				})
			}
		}
	}
	return out
}

func looksLikeReq(s string) bool {
	if s == "" || strings.Contains(s, " ") && !strings.Contains(s, "==") && !strings.Contains(s, "@") {
		return false
	}
	name, _, _, ok := parseReq(s)
	return ok && name != ""
}

func poetryVersion(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "{") {
		for _, q := range quotedStrings(value) {
			if isExactVersion(q) {
				return q
			}
		}
		return ""
	}
	v := unquote(value)
	if isExactVersion(v) {
		return v
	}
	return ""
}

func parseRequirements(manifest string, data []byte) []model.Dep {
	var out []model.Dep
	for _, line := range strings.Split(string(data), "\n") {
		line = stripLineComment(line)
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		name, ver, hint, ok := parseReq(line)
		if !ok {
			continue
		}
		d := model.Dep{Ecosystem: "pypi", Name: name, Version: ver, Direct: true, Manifest: manifest, RepoHint: hint}
		if hint != "" && ver == "" {
			d.SkipRegistry = true
		}
		out = append(out, d)
	}
	return out
}

func parseReq(line string) (name, version, hint string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", "", false
	}
	if i := strings.Index(line, ";"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	if strings.Contains(line, "://") || strings.HasPrefix(line, "git+") {
		hint = repo.ProjectID(line)
		if egg := eggName(line); egg != "" {
			return egg, "", hint, true
		}
		if hint != "" {
			return hint, "", hint, true
		}
		return "", "", "", false
	}
	if i := strings.Index(line, "["); i >= 0 {
		if j := strings.Index(line[i:], "]"); j >= 0 {
			line = line[:i] + line[i+j+1:]
		}
	}
	for _, op := range []string{"===", "==", ">=", "<=", "~=", "!=", ">", "<"} {
		if i := strings.Index(line, op); i >= 0 {
			name = strings.TrimSpace(line[:i])
			rest := strings.TrimSpace(line[i+len(op):])
			if sp := strings.IndexAny(rest, ", "); sp >= 0 {
				rest = rest[:sp]
			}
			if (op == "==" || op == "===") && isExactVersion(rest) {
				version = rest
			}
			return name, version, "", name != ""
		}
	}
	if isName(line) {
		return line, "", "", true
	}
	return "", "", "", false
}

func eggName(line string) string {
	if i := strings.Index(line, "#"); i >= 0 {
		frag := line[i+1:]
		for _, part := range strings.Split(frag, "&") {
			if strings.HasPrefix(part, "egg=") {
				return strings.TrimPrefix(part, "egg=")
			}
		}
	}
	return ""
}

func isName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			continue
		}
		return false
	}
	return true
}

func parsePythonLock(manifest string, data []byte) []model.Dep {
	var out []model.Dep
	var name, version, source string
	skip := false
	var hint string
	flush := func() {
		if name != "" && version != "" && !skip {
			d := model.Dep{Ecosystem: "pypi", Name: name, Version: version, Manifest: manifest, RepoHint: hint}
			if hint != "" {
				d.SkipRegistry = true
			}
			out = append(out, d)
		}
		name, version, source, hint = "", "", "", ""
		skip = false
	}
	for _, line := range strings.Split(string(data), "\n") {
		trim := stripLineComment(line)
		if trim == "[[package]]" {
			flush()
			continue
		}
		if strings.HasPrefix(trim, "[") && trim != "[[package]]" {
			continue
		}
		k, v, ok := splitAssign(trim)
		if !ok {
			continue
		}
		switch k {
		case "name":
			name = unquote(v)
		case "version":
			version = unquote(v)
		case "source":
			source = v
			if strings.Contains(source, "directory") || strings.Contains(source, "virtual") || strings.Contains(source, "editable") {
				skip = true
			}
			if id := repo.ProjectID(source); id != "" && strings.Contains(source, "git") {
				hint = id
			}
		case "type":
			t := unquote(v)
			if t == "directory" || t == "file" || t == "editable" {
				skip = true
			}
		case "url":
			if id := repo.ProjectID(unquote(v)); id != "" {
				hint = id
			}
		}
	}
	flush()
	return out
}
