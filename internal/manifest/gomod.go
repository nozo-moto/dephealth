package manifest

import (
	"path/filepath"
	"strings"

	"github.com/nozo-moto/dephealth/internal/model"
	"golang.org/x/mod/modfile"
)

func parseGoMod(path string, data []byte) ([]model.Dep, error) {
	// Parse は replace を残す。ParseLax は依存モジュール向けに replace を捨てる。
	f, err := modfile.Parse(filepath.Base(path), data, nil)
	if err != nil {
		f, err = modfile.ParseLax(filepath.Base(path), data, nil)
		if err != nil {
			return nil, err
		}
	}
	var out []model.Dep
	for _, req := range f.Require {
		modPath, ver := req.Mod.Path, req.Mod.Version
		skip := false
		for _, r := range f.Replace {
			if r.Old.Path != req.Mod.Path {
				continue
			}
			if r.Old.Version != "" && r.Old.Version != req.Mod.Version {
				continue
			}
			if isLocalPath(r.New.Path) {
				skip = true
				break
			}
			modPath = r.New.Path
			if r.New.Version != "" {
				ver = r.New.Version
			}
		}
		if skip || modPath == "" || ver == "" {
			continue
		}
		out = append(out, model.Dep{
			Ecosystem: "go",
			Name:      modPath,
			Version:   ver,
			Direct:    !req.Indirect,
			Manifest:  path,
		})
	}
	return out, nil
}

func isLocalPath(p string) bool {
	return strings.HasPrefix(p, "./") ||
		strings.HasPrefix(p, "../") ||
		strings.HasPrefix(p, "/") ||
		strings.HasPrefix(p, ".\\") ||
		strings.HasPrefix(p, "..\\")
}
