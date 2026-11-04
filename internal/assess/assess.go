// Package assess は依存 1 件を Scorecard・更新日・ライセンスから判定する。
package assess

import (
	"fmt"
	"strings"
	"time"

	"github.com/nozo-moto/dephealth/internal/depsdev"
	"github.com/nozo-moto/dephealth/internal/license"
	"github.com/nozo-moto/dephealth/internal/model"
)

// Options は判定の閾値。
type Options struct {
	MinScore      float64
	MinMaintained int
	StaleDays     int
	License       license.Policy
}

// Input は 1 件分の照会結果。取れていないものは nil または空。
type Input struct {
	Dep          model.Dep
	Version      *depsdev.Version
	Package      *depsdev.Package
	Project      *depsdev.Project
	Repository   string
	Provenance   string
	LookupError  string
	NotFound     bool
	ProjectError string
}

// Evaluate は指摘を付けた結果を返す。
func Evaluate(in Input, opt Options) model.Result {
	d := in.Dep
	res := model.Result{
		Ecosystem:  d.Ecosystem,
		Name:       d.Name,
		Version:    d.Version,
		Direct:     d.Direct,
		Dev:        d.Dev,
		Repository: in.Repository,
		Provenance: in.Provenance,
		Checks:     map[string]int{},
	}
	if d.Manifest != "" {
		res.Manifests = strings.Split(d.Manifest, "\n")
	}
	if in.Version != nil {
		if in.Version.Version != "" {
			res.Version = in.Version.Version
		}
		res.PublishedAt = in.Version.PublishedAt
		res.Licenses = append([]string(nil), in.Version.Licenses...)
		res.Advisories = append([]string(nil), in.Version.Advisories...)
	}
	if in.Package != nil {
		res.LatestVersion = in.Package.DefaultVersion
		res.LatestPublished = in.Package.DefaultPublished
	}
	if in.Project != nil {
		res.Stars = in.Project.Stars
		res.Score = in.Project.Score
		res.ScoreDate = in.Project.ScoreDate
		for name, c := range in.Project.Checks {
			res.Checks[name] = c.Score
		}
		if c, ok := in.Project.Checks["Maintained"]; ok {
			score := c.Score
			res.Maintained = &score
			res.MaintainedReason = c.Reason
		}
	}

	add := func(sev model.Severity, code, msg string) {
		res.Findings = append(res.Findings, model.Finding{
			Severity: sev,
			Code:     code,
			Message:  trim(msg, 300),
		})
	}

	if d.Version == "" {
		add(model.SevMedium, model.CodeUnpinned, "版が固定されていません。ロックファイルが無いか、範囲指定のままです")
	}
	if in.LookupError != "" {
		res.LookupError = in.LookupError
		add(model.SevMedium, model.CodeLookup, "照会に失敗しました: "+in.LookupError)
	} else if in.NotFound && in.Repository == "" {
		add(model.SevMedium, model.CodeNoRepo, "deps.dev にこの版がなく、ソースリポジトリも特定できません")
	} else if in.NotFound {
		add(model.SevMedium, model.CodeLookup, "deps.dev にこの版がありません。リポジトリはマニフェストから推定しています")
	} else if d.Version != "" && in.Repository == "" && in.LookupError == "" {
		add(model.SevMedium, model.CodeNoRepo, "ソースリポジトリを特定できません")
	}

	if in.Version != nil && len(in.Version.Advisories) > 0 {
		ids := in.Version.Advisories
		msg := "既知の脆弱性: " + strings.Join(limit(ids, 8), ", ")
		if len(ids) > 8 {
			msg += fmt.Sprintf(" ほか %d 件", len(ids)-8)
		}
		add(model.SevHigh, model.CodeAdvisory, msg)
	}
	if in.Version != nil && in.Version.Deprecated {
		msg := "この版はレジストリ上で非推奨です"
		if in.Version.DeprecatedReason != "" {
			msg += ": " + in.Version.DeprecatedReason
		}
		add(model.SevHigh, model.CodeDeprecated, msg)
	}
	if in.Version != nil {
		switch strings.ToLower(in.Version.ProjectStatus) {
		case "archived", "deprecated", "obsolete":
			add(model.SevHigh, model.CodeProjectStatus, statusMsg(in.Version))
		case "inactive", "unsupported", "suspended":
			add(model.SevMedium, model.CodeProjectStatus, statusMsg(in.Version))
		}
	}

	if d.Version == "" && in.Version == nil && (in.Project == nil || strings.TrimSpace(in.Project.License) == "") {
		res.LicenseSummary = "未確認"
	} else {
		judgeLicense(&res, in, opt, add)
	}

	if in.ProjectError != "" {
		add(model.SevMedium, model.CodeLookup, "Scorecard の取得に失敗しました: "+in.ProjectError)
	} else if in.Repository != "" && (in.Project == nil || in.Project.Score == nil) && in.LookupError == "" {
		add(model.SevLow, model.CodeNoScorecard, "OpenSSF Scorecard がありません")
	}

	if in.Project != nil && in.Project.Score != nil && *in.Project.Score < opt.MinScore {
		add(model.SevMedium, model.CodeLowScore, fmt.Sprintf("OpenSSF Scorecard の総合スコアが %.1f で、閾値 %.1f を下回っています", *in.Project.Score, opt.MinScore))
	}
	if c, ok := check(in.Project, "Maintained"); ok {
		if c.Score == 0 {
			add(model.SevHigh, model.CodeUnmaintained, "保守が止まっています: "+emptyReason(c.Reason, "Maintained が 0 です"))
		} else if c.Score < opt.MinMaintained {
			add(model.SevMedium, model.CodeLowMaintained, fmt.Sprintf("保守スコアが %d で、閾値 %d を下回っています: %s", c.Score, opt.MinMaintained, emptyReason(c.Reason, "")))
		}
	}
	if c, ok := check(in.Project, "Dangerous-Workflow"); ok && c.Score < 10 {
		add(model.SevHigh, model.CodeDangerousWorkflow, "危険な GitHub Actions があります: "+emptyReason(c.Reason, "Dangerous-Workflow が失敗しています"))
	}
	if c, ok := check(in.Project, "Binary-Artifacts"); ok && c.Score < 10 {
		add(model.SevMedium, model.CodeBinary, "リポジトリにバイナリが混ざっています: "+emptyReason(c.Reason, "Binary-Artifacts が失敗しています"))
	}
	if c, ok := check(in.Project, "Vulnerabilities"); ok && c.Score < 10 {
		add(model.SevMedium, model.CodeVulnerabilities, "Scorecard の Vulnerabilities が失敗しています: "+emptyReason(c.Reason, ""))
	}

	if opt.StaleDays > 0 && in.Version != nil && in.Package != nil &&
		in.Package.DefaultVersion != "" && in.Package.DefaultVersion != res.Version &&
		!in.Version.PublishedAt.IsZero() && !in.Package.DefaultPublished.IsZero() {
		days := int(in.Package.DefaultPublished.Sub(in.Version.PublishedAt).Hours() / 24)
		if days >= opt.StaleDays {
			add(model.SevMedium, model.CodeStale, fmt.Sprintf("最新版 %s（%s）より %d 日古い版です", in.Package.DefaultVersion, in.Package.DefaultPublished.UTC().Format("2006-01-02"), days))
		}
	}
	return res
}

func judgeLicense(res *model.Result, in Input, opt Options, add func(model.Severity, string, string)) {
	lics := []string{}
	fromHost := false
	if in.Version != nil {
		for _, s := range in.Version.Licenses {
			if strings.TrimSpace(s) != "" {
				lics = append(lics, s)
			}
		}
	}
	if len(lics) == 0 && in.Project != nil {
		if h := license.NormalizeHost(in.Project.License); h != "" {
			lics = []string{h}
			fromHost = true
		}
	}
	v := license.Judge(lics, opt.License)
	res.Licenses = lics
	res.LicenseSummary = v.Summary
	if opt.License.Enabled && v.Severity > model.SevNone {
		msg := v.Summary
		if fromHost {
			msg += "（パッケージメタデータに無く、リポジトリの表示を使っています）"
		}
		add(v.Severity, model.CodeLicense, msg)
	}

	if opt.License.Enabled && in.Version != nil && len(in.Version.Licenses) == 1 && in.Project != nil && !strings.Contains(in.Version.Licenses[0], " ") {
		host := license.NormalizeHost(in.Project.License)
		if host != "" && license.Family(in.Version.Licenses[0]) != license.Family(host) {
			add(model.SevLow, model.CodeLicenseMismatch, fmt.Sprintf("パッケージは %s、リポジトリの表示は %s です", in.Version.Licenses[0], host))
		}
	}
}

func check(p *depsdev.Project, name string) (depsdev.Check, bool) {
	if p == nil {
		return depsdev.Check{}, false
	}
	c, ok := p.Checks[name]
	return c, ok
}

func statusMsg(v *depsdev.Version) string {
	msg := "プロジェクト状態が " + v.ProjectStatus + " です"
	if v.ProjectStatusReason != "" {
		msg += ": " + v.ProjectStatusReason
	}
	return msg
}

func emptyReason(reason, fallback string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return fallback
	}
	return reason
}

func limit(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func trim(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// DaysBetween はテストから日付差を確認するための補助。
func DaysBetween(newer, older time.Time) int {
	return int(newer.Sub(older).Hours() / 24)
}
