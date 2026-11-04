// Package scan はマニフェストを読み、deps.dev に問い合わせ、判定まで行う。
package scan

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/nozo-moto/dephealth/internal/assess"
	"github.com/nozo-moto/dephealth/internal/depsdev"
	"github.com/nozo-moto/dephealth/internal/manifest"
	"github.com/nozo-moto/dephealth/internal/model"
	"github.com/nozo-moto/dephealth/internal/repo"
)

// Option は scan 全体の設定。
type Option struct {
	DirectOnly    bool
	Concurrency   int
	DepsDevURL    string
	Ignore        []string
	MinScore      float64
	MinMaintained int
	StaleDays     int
	Assess        assess.Options
}

// Run は roots を走査する。
func Run(ctx context.Context, roots []string, opt Option) (*model.Report, error) {
	if opt.Concurrency < 1 {
		opt.Concurrency = 8
	}
	deps, manifests, warnings, err := manifest.Discover(roots, opt.DirectOnly, opt.Ignore)
	if err != nil {
		return nil, err
	}
	client := depsdev.New(opt.DepsDevURL, opt.Concurrency)
	aopt := opt.Assess
	if aopt.MinScore == 0 && opt.MinScore != 0 {
		aopt.MinScore = opt.MinScore
	}
	if aopt.MinMaintained == 0 && opt.MinMaintained != 0 {
		aopt.MinMaintained = opt.MinMaintained
	}
	if aopt.StaleDays == 0 && opt.StaleDays != 0 {
		aopt.StaleDays = opt.StaleDays
	}

	type looked struct {
		ver      *depsdev.Version
		pkg      *depsdev.Package
		notFound bool
		err      string
	}
	got := make([]looked, len(deps))
	var wg sync.WaitGroup
	for i, d := range deps {
		if d.Version == "" || d.SkipRegistry {
			continue
		}
		wg.Add(1)
		go func(i int, d model.Dep) {
			defer wg.Done()
			if ctx.Err() != nil {
				got[i].err = ctx.Err().Error()
				return
			}
			sys := system(d.Ecosystem)
			ver, verr := client.Version(ctx, sys, d.Name, d.Version)
			pkg, _ := client.Package(ctx, sys, d.Name)
			if errors.Is(verr, depsdev.ErrNotFound) {
				got[i].notFound = true
			} else if verr != nil {
				got[i].err = verr.Error()
			} else {
				got[i].ver = ver
			}
			got[i].pkg = pkg
		}(i, d)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	repoOf := make([]string, len(deps))
	provOf := make([]string, len(deps))
	ids := map[string]struct{}{}
	for i, d := range deps {
		id, prov := "", ""
		if got[i].ver != nil {
			id, prov = got[i].ver.ProjectID, got[i].ver.Provenance
		}
		if id == "" && d.RepoHint != "" {
			id = d.RepoHint
			if prov == "" {
				prov = "VCS"
			}
		}
		if id == "" && d.Ecosystem == "go" {
			if inf, kind := repo.InferGo(d.Name); inf != "" {
				id = inf
				if prov == "" {
					prov = kind
				}
			}
		}
		repoOf[i] = id
		provOf[i] = prov
		if id != "" {
			ids[id] = struct{}{}
		}
	}

	projects := map[string]*depsdev.Project{}
	perrs := map[string]string{}
	var mu sync.Mutex
	for id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			p, err := client.Project(ctx, id)
			mu.Lock()
			defer mu.Unlock()
			if errors.Is(err, depsdev.ErrNotFound) {
				perrs[id] = "deps.dev にこのリポジトリがありません"
				return
			}
			if err != nil {
				perrs[id] = err.Error()
				return
			}
			projects[id] = p
		}(id)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	results := make([]model.Result, 0, len(deps))
	for i, d := range deps {
		in := assess.Input{
			Dep:          d,
			Version:      got[i].ver,
			Package:      got[i].pkg,
			Repository:   repoOf[i],
			Provenance:   provOf[i],
			LookupError:  got[i].err,
			NotFound:     got[i].notFound,
			ProjectError: perrs[repoOf[i]],
		}
		if p, ok := projects[repoOf[i]]; ok {
			in.Project = p
		}
		results = append(results, assess.Evaluate(in, aopt))
	}
	sort.Slice(results, func(i, j int) bool {
		si, sj := results[i].MaxSeverity(), results[j].MaxSeverity()
		if si != sj {
			return si > sj
		}
		if results[i].Ecosystem != results[j].Ecosystem {
			return results[i].Ecosystem < results[j].Ecosystem
		}
		if results[i].Name != results[j].Name {
			return results[i].Name < results[j].Name
		}
		return results[i].Version < results[j].Version
	})
	return &model.Report{
		ScannedAt: time.Now().UTC(),
		Roots:     roots,
		Manifests: manifests,
		Warnings:  warnings,
		Results:   results,
	}, nil
}

func system(eco string) string {
	switch eco {
	case "go", "npm", "pypi", "cargo", "rubygems":
		return eco
	default:
		return eco
	}
}
