package manifest

import (
	"path/filepath"
	"strings"

	"github.com/nozo-moto/dephealth/internal/model"
)

func parseGemDir(dir string) ([]model.Dep, error) {
	lock := filepath.Join(dir, "Gemfile.lock")
	if exists(lock) {
		b, err := readFile(lock)
		if err != nil {
			return nil, err
		}
		return parseGemfileLock(lock, b), nil
	}
	gemfile := filepath.Join(dir, "Gemfile")
	if !exists(gemfile) {
		return nil, nil
	}
	b, err := readFile(gemfile)
	if err != nil {
		return nil, err
	}
	return parseGemfile(gemfile, b), nil
}

func parseGemfileLock(manifest string, data []byte) []model.Dep {
	lines := strings.Split(string(data), "\n")
	direct := map[string]bool{}
	inDeps := false
	var specs []model.Dep
	inSpecs := false
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		switch trim {
		case "DEPENDENCIES":
			inDeps = true
			inSpecs = false
			continue
		case "GEM", "PLATFORMS", "BUNDLED WITH", "PATH", "GIT", "PLUGIN SOURCE":
			if trim != "GEM" {
				inSpecs = false
			}
			inDeps = false
		}
		if inDeps {
			if trim == "" || strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "  ") {
				continue
			}
			if !strings.HasPrefix(line, "  ") {
				inDeps = false
				continue
			}
			name := trim
			if i := strings.IndexAny(name, " (!"); i >= 0 {
				name = strings.TrimSpace(name[:i])
			}
			if name != "" {
				direct[name] = true
			}
			continue
		}
		if trim == "specs:" {
			inSpecs = true
			continue
		}
		if inSpecs {
			if strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     ") {
				name, ver, ok := gemSpec(trim)
				if ok {
					specs = append(specs, model.Dep{
						Ecosystem: "rubygems",
						Name:      name,
						Version:   ver,
						Direct:    direct[name],
						Manifest:  manifest,
					})
				}
				continue
			}
			if trim != "" && !strings.HasPrefix(line, " ") {
				inSpecs = false
			}
		}
	}
	// DEPENDENCIES は specs より後に来ることが多い。もう一度 Direct を付ける。
	for i := range specs {
		specs[i].Direct = direct[specs[i].Name]
	}
	return specs
}

func gemSpec(trim string) (string, string, bool) {
	i := strings.Index(trim, " (")
	if i <= 0 || !strings.HasSuffix(trim, ")") {
		return "", "", false
	}
	name := trim[:i]
	ver := strings.TrimSuffix(trim[i+2:], ")")
	if name == "" || ver == "" || strings.Contains(ver, " ") {
		return "", "", false
	}
	return name, ver, true
}

func parseGemfile(manifest string, data []byte) []model.Dep {
	var out []model.Dep
	for _, line := range strings.Split(string(data), "\n") {
		trim := stripLineComment(line)
		trim = strings.TrimSpace(trim)
		if !strings.HasPrefix(trim, "gem ") && !strings.HasPrefix(trim, "gem(") {
			continue
		}
		qs := quotedStrings(trim)
		if len(qs) == 0 {
			continue
		}
		d := model.Dep{Ecosystem: "rubygems", Name: qs[0], Direct: true, Manifest: manifest}
		if len(qs) > 1 && isExactVersion(qs[1]) {
			d.Version = qs[1]
		}
		out = append(out, d)
	}
	return out
}
