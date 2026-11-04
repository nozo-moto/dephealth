package manifest

import (
	"path/filepath"
	"strings"

	"github.com/nozo-moto/dephealth/internal/model"
	"github.com/nozo-moto/dephealth/internal/repo"
)

func parseCargoDir(dir string) ([]model.Dep, error) {
	direct := map[string]bool{}
	tomlPath := filepath.Join(dir, "Cargo.toml")
	if exists(tomlPath) {
		b, err := readFile(tomlPath)
		if err != nil {
			return nil, err
		}
		for _, name := range cargoDirectNames(string(b)) {
			direct[name] = true
		}
	}
	lockPath := filepath.Join(dir, "Cargo.lock")
	if !exists(lockPath) {
		var out []model.Dep
		for name := range direct {
			out = append(out, model.Dep{
				Ecosystem: "cargo",
				Name:      name,
				Direct:    true,
				Manifest:  tomlPath,
			})
		}
		return out, nil
	}
	b, err := readFile(lockPath)
	if err != nil {
		return nil, err
	}
	return parseCargoLock(lockPath, b, direct), nil
}

func cargoDirectNames(data string) []string {
	var names []string
	seen := map[string]bool{}
	for _, sec := range splitTOML(data) {
		if n, ok := depNameFromSection(sec.name); ok {
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
			continue
		}
		if !isDepTable(sec.name) {
			continue
		}
		for name := range assignments(sec.lines) {
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	return names
}

func isDepTable(name string) bool {
	base := name
	if i := strings.LastIndex(name, "."); i >= 0 {
		base = name[i+1:]
	}
	base = strings.Trim(base, `"'`)
	switch base {
	case "dependencies", "dev-dependencies", "build-dependencies":
		return true
	default:
		return false
	}
}

func depNameFromSection(name string) (string, bool) {
	parts := splitDots(name)
	for i, p := range parts {
		p = strings.Trim(p, `"'`)
		if p == "dependencies" || p == "dev-dependencies" || p == "build-dependencies" {
			if i+1 < len(parts) {
				n := strings.Trim(parts[i+1], `"'`)
				if n != "" {
					return n, true
				}
			}
			return "", false
		}
	}
	return "", false
}

func splitDots(s string) []string {
	var out []string
	var b strings.Builder
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			b.WriteByte(c)
			continue
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
			b.WriteByte(c)
			continue
		}
		if c == '.' && !inSingle && !inDouble {
			out = append(out, b.String())
			b.Reset()
			continue
		}
		b.WriteByte(c)
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

type cargoPkg struct {
	name, version, source string
}

func parseCargoLock(manifest string, data []byte, direct map[string]bool) []model.Dep {
	var blocks []cargoPkg
	var cur *cargoPkg
	flush := func() {
		if cur != nil && cur.name != "" && cur.version != "" {
			blocks = append(blocks, *cur)
		}
		cur = nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		trim := stripLineComment(line)
		if trim == "[[package]]" {
			flush()
			cur = &cargoPkg{}
			continue
		}
		if cur == nil || !strings.HasPrefix(line, "name") && !strings.HasPrefix(strings.TrimSpace(line), "name") &&
			!strings.HasPrefix(strings.TrimSpace(line), "version") && !strings.HasPrefix(strings.TrimSpace(line), "source") {
			if strings.HasPrefix(trim, "[") {
				flush()
			}
			continue
		}
		k, v, ok := splitAssign(trim)
		if !ok {
			continue
		}
		switch k {
		case "name":
			cur.name = unquote(v)
		case "version":
			cur.version = unquote(v)
		case "source":
			cur.source = unquote(v)
		}
	}
	flush()
	var out []model.Dep
	for _, p := range blocks {
		if p.source == "" {
			continue
		}
		d := model.Dep{
			Ecosystem: "cargo",
			Name:      p.name,
			Version:   p.version,
			Direct:    direct[p.name],
			Manifest:  manifest,
		}
		if strings.HasPrefix(p.source, "git+") {
			d.RepoHint = repo.ProjectID(strings.TrimPrefix(p.source, "git+"))
			d.SkipRegistry = true
		} else if !strings.Contains(p.source, "registry+") {
			continue
		}
		out = append(out, d)
	}
	return out
}
