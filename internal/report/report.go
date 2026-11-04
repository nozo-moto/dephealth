// Package report は scan 結果をテキスト、Markdown、JSON にする。
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/nozo-moto/dephealth/internal/model"
	"github.com/nozo-moto/dephealth/internal/repo"
)

// View は人間向け出力でどこまで出すか。
type View struct {
	Verbose       bool
	All           bool
	MinScore      float64
	MinMaintained int
	FailAt        model.Severity
}

var jst = time.FixedZone("JST", 9*60*60)

// Text はターミナル向けの要約を書く。
func Text(w io.Writer, rep *model.Report, view View) {
	fmt.Fprint(w, render(rep, view, false))
}

// Markdown は GitHub Issue 向けの本文を返す。先頭に更新用のマーカーは付けない。
func Markdown(rep *model.Report, view View) string {
	return render(rep, view, true)
}

func render(rep *model.Report, view View, md bool) string {
	var b strings.Builder
	line := func(format string, args ...any) {
		fmt.Fprintf(&b, format+"\n", args...)
	}
	if md {
		line("## dephealth")
		line("")
	} else {
		line("dephealth")
		line("")
	}
	when := rep.ScannedAt.In(jst).Format("2006-01-02 15:04 MST")
	line("走査日時: %s", when)
	if len(rep.Roots) > 0 {
		line("対象: %s", strings.Join(rep.Roots, ", "))
	}
	direct, repos := 0, map[string]bool{}
	for _, r := range rep.Results {
		if r.Direct {
			direct++
		}
		if r.Repository != "" {
			repos[r.Repository] = true
		}
	}
	line("マニフェスト: %d", rep.Manifests)
	line("パッケージ: %d（直接 %d / それ以外 %d）", len(rep.Results), direct, len(rep.Results)-direct)
	line("リポジトリ: %d", len(repos))
	counts := countFindings(rep)
	line("指摘: 高 %d / 中 %d / 低 %d", counts[model.SevHigh], counts[model.SevMedium], counts[model.SevLow])
	line("")
	line("ソースの対応づけ: %s", provenanceSummary(rep))
	line("")
	writeLicenses(&b, rep, md)
	line("")
	writeRepoScorecard(&b, rep, view, md)
	if len(rep.Warnings) > 0 {
		line("")
		line("警告:")
		for _, w := range rep.Warnings {
			line("- %s", w)
		}
	}
	line("")
	shown := writeDetails(&b, rep, view, md)
	hiddenLow := counts[model.SevLow]
	if !view.Verbose && !view.All {
		shownLow := 0
		for _, r := range rep.Results {
			for _, f := range r.Findings {
				if f.Severity == model.SevLow {
					shownLow++
				}
			}
		}
		_ = shownLow
		if hiddenLow > 0 {
			line("")
			line("低リスクの指摘 %d 件は --verbose で表示します。", hiddenLow)
		}
	}
	if shown == 0 && !view.All && !md {
		line("閾値以上の指摘はありません。")
	}
	line("")
	line("判定は deps.dev が配布する OpenSSF Scorecard とパッケージメタデータに基づきます。ライセンス分類は法的助言ではありません。")
	line("保守が止まっている公開パッケージは、放置された権限が乗っ取られる型のサプライチェーン攻撃の条件になります。")
	return b.String()
}

func writeLicenses(b *strings.Builder, rep *model.Report, md bool) {
	type row struct {
		label string
		n     int
		sev   model.Severity
	}
	by := map[string]*row{}
	var order []string
	ok, review := 0, 0
	for _, r := range rep.Results {
		label := r.LicenseSummary
		if label == "" {
			label = "未記載"
		}
		sev := licenseSev(r)
		if sev == model.SevNone {
			ok++
		} else {
			review++
		}
		if _, exists := by[label]; !exists {
			by[label] = &row{label: label, sev: sev}
			order = append(order, label)
		}
		by[label].n++
		if sev > by[label].sev {
			by[label].sev = sev
		}
	}
	fmt.Fprintf(b, "ライセンス: 問題なし %d / 要確認 %d\n", ok, review)
	sort.Slice(order, func(i, j int) bool {
		a, c := by[order[i]], by[order[j]]
		if a.sev != c.sev {
			return a.sev > c.sev
		}
		if a.n != c.n {
			return a.n > c.n
		}
		return a.label < c.label
	})
	limit := 12
	if len(order) < limit {
		limit = len(order)
	}
	for _, k := range order[:limit] {
		row := by[k]
		mark := ""
		if row.sev > model.SevNone {
			mark = "（" + row.sev.Label() + "）"
		}
		if md {
			fmt.Fprintf(b, "- `%s` %d%s\n", strings.ReplaceAll(row.label, "`", "'"), row.n, mark)
		} else {
			fmt.Fprintf(b, "  %s: %d%s\n", row.label, row.n, mark)
		}
	}
	if len(order) > limit {
		fmt.Fprintf(b, "  …ほか %d 種類\n", len(order)-limit)
	}
}

func licenseSev(r model.Result) model.Severity {
	m := model.SevNone
	for _, f := range r.Findings {
		if f.Code == model.CodeLicense && f.Severity > m {
			m = f.Severity
		}
	}
	return m
}

func writeRepoScorecard(b *strings.Builder, rep *model.Report, view View, md bool) {
	type agg struct {
		lowScore, lowMaint, workflow, binary, token, noCard int
	}
	seen := map[string]bool{}
	var a agg
	for _, r := range rep.Results {
		if r.Repository == "" || seen[r.Repository] {
			continue
		}
		seen[r.Repository] = true
		if r.Score != nil && *r.Score < view.MinScore {
			a.lowScore++
		}
		if r.Maintained != nil && *r.Maintained < view.MinMaintained {
			a.lowMaint++
		}
		if s, ok := r.Checks["Dangerous-Workflow"]; ok && s < 10 {
			a.workflow++
		}
		if s, ok := r.Checks["Binary-Artifacts"]; ok && s < 10 {
			a.binary++
		}
		if s, ok := r.Checks["Token-Permissions"]; ok && s < 10 {
			a.token++
		}
		if r.Score == nil {
			a.noCard++
		}
	}
	fmt.Fprintf(b, "リポジトリ単位の Scorecard:\n")
	fmt.Fprintf(b, "- 総合スコア %.1f 未満: %d\n", view.MinScore, a.lowScore)
	fmt.Fprintf(b, "- 保守スコア %d 未満: %d\n", view.MinMaintained, a.lowMaint)
	fmt.Fprintf(b, "- Dangerous-Workflow が失敗: %d\n", a.workflow)
	fmt.Fprintf(b, "- Binary-Artifacts が失敗: %d\n", a.binary)
	fmt.Fprintf(b, "- Token-Permissions が広い: %d\n", a.token)
	fmt.Fprintf(b, "- Scorecard なし: %d\n", a.noCard)
	if a.workflow > 0 {
		fmt.Fprintf(b, "\nDangerous-Workflow が失敗しているリポジトリは、信頼できないコードの checkout と secret の組み合わせなど、GitHub Actions 経由で改変されうるパターンがあります。\n")
	}
	if a.token > 0 {
		fmt.Fprintf(b, "\nToken-Permissions が広いリポジトリは、Actions の GITHUB_TOKEN に書き込み権限があります。依存先の CI が侵害されたときの影響が広がります。件数が多いのは、この検査が厳しめなためです。\n")
	}
	_ = md
}

func writeDetails(b *strings.Builder, rep *model.Report, view View, md bool) int {
	min := model.SevMedium
	if view.Verbose {
		min = model.SevLow
	}
	if view.All {
		min = model.SevNone
	}
	shown := 0
	if md {
		fmt.Fprintf(b, "\n### パッケージ\n\n")
		fmt.Fprintf(b, "| 重大度 | パッケージ | 版 | リポジトリ | Score | 保守 | ライセンス | 内容 |\n")
		fmt.Fprintf(b, "| --- | --- | --- | --- | --- | --- | --- | --- |\n")
	}
	for _, r := range rep.Results {
		if r.MaxSeverity() < min && !view.All {
			continue
		}
		if !view.All && r.MaxSeverity() == model.SevNone {
			continue
		}
		shown++
		if md {
			fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
				cell(r.MaxSeverity().Label()),
				cell(r.Ecosystem+"/"+r.Name),
				cell(emptyDash(r.Version)),
				cell(repoLink(r.Repository)),
				cell(scoreText(r)),
				cell(maintText(r)),
				cell(r.LicenseSummary),
				cell(findingText(r, min)),
			)
			continue
		}
		rel := "間接"
		if r.Direct {
			rel = "直接"
		}
		fmt.Fprintf(b, "[%s] %s %s@%s（%s）\n", emptyLabel(r.MaxSeverity()), r.Ecosystem, r.Name, emptyDash(r.Version), rel)
		if r.Repository != "" {
			fmt.Fprintf(b, "  リポジトリ: %s", repo.URL(r.Repository))
			if label := provenanceLabel(r.Provenance); label != "" {
				fmt.Fprintf(b, "（%s）", label)
			}
			fmt.Fprintln(b)
		}
		fmt.Fprintf(b, "  Scorecard: %s  保守: %s  ライセンス: %s", scoreText(r), maintText(r), emptyDash(r.LicenseSummary))
		if r.Stars > 0 {
			fmt.Fprintf(b, "  スター: %d", r.Stars)
		}
		fmt.Fprintln(b)
		if len(r.Manifests) > 0 {
			fmt.Fprintf(b, "  マニフェスト: %s\n", strings.Join(r.Manifests, ", "))
		}
		for _, f := range r.Findings {
			if f.Severity < min && !view.All {
				continue
			}
			fmt.Fprintf(b, "  - %s: %s\n", f.Severity.Label(), f.Message)
		}
		fmt.Fprintln(b)
	}
	if md && shown == 0 {
		fmt.Fprintf(b, "| - | - | - | - | - | - | - | 閾値以上の指摘はありません |\n")
	}
	return shown
}

func findingText(r model.Result, min model.Severity) string {
	var parts []string
	for _, f := range r.Findings {
		if f.Severity < min {
			continue
		}
		parts = append(parts, f.Severity.Label()+": "+f.Message)
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " / ")
}

func scoreText(r model.Result) string {
	if r.Score == nil {
		return "-"
	}
	s := fmt.Sprintf("%.1f", *r.Score)
	if !r.ScoreDate.IsZero() {
		s += " / " + r.ScoreDate.UTC().Format("2006-01-02")
	}
	return s
}

func maintText(r model.Result) string {
	if r.Maintained == nil {
		return "-"
	}
	return fmt.Sprintf("%d", *r.Maintained)
}

func repoLink(id string) string {
	if id == "" {
		return "-"
	}
	return id
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func emptyLabel(s model.Severity) string {
	if s.Label() == "" {
		return "-"
	}
	return s.Label()
}

func cell(s string) string {
	s = strings.ReplaceAll(s, "|", "/")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	r := []rune(s)
	if len(r) > 160 {
		return string(r[:159]) + "…"
	}
	return s
}

func countFindings(rep *model.Report) map[model.Severity]int {
	m := map[model.Severity]int{}
	for _, r := range rep.Results {
		for _, f := range r.Findings {
			m[f.Severity]++
		}
	}
	return m
}

func provenanceLabel(p string) string {
	switch p {
	case "GO_ORIGIN":
		return "Go モジュールの起源"
	case "SLSA_ATTESTATION":
		return "検証済みの SLSA"
	case "PYPI_PUBLISH_ATTESTATION":
		return "PyPI の公開証明"
	case "RUBYGEMS_PUBLISH_ATTESTATION":
		return "RubyGems の公開証明"
	case "UNVERIFIED_METADATA":
		return "未検証のメタデータ"
	case "LINK":
		return "パッケージのリンク"
	case "VCS":
		return "マニフェストの VCS 指定"
	case "INFERRED":
		return "モジュールパスから推定"
	case "GO_MIRROR":
		return "go.googlesource.com の GitHub ミラー"
	default:
		return p
	}
}

func provenanceSummary(rep *model.Report) string {
	var verified, meta, vcs, inferred, unknown int
	for _, r := range rep.Results {
		switch r.Provenance {
		case "SLSA_ATTESTATION", "PYPI_PUBLISH_ATTESTATION", "RUBYGEMS_PUBLISH_ATTESTATION", "GO_ORIGIN":
			verified++
		case "UNVERIFIED_METADATA", "LINK":
			meta++
		case "VCS":
			vcs++
		case "INFERRED", "GO_MIRROR":
			inferred++
		default:
			if r.Repository == "" {
				unknown++
			} else {
				meta++
			}
		}
	}
	return fmt.Sprintf("検証済み %d / メタデータのみ %d / VCS 指定 %d / 推定 %d / 不明 %d", verified, meta, vcs, inferred, unknown)
}

// ShouldFail は failAt 以上の指摘があるかを返す。
func ShouldFail(rep *model.Report, failAt model.Severity) bool {
	for _, r := range rep.Results {
		for _, f := range r.Findings {
			if f.Severity >= failAt {
				return true
			}
		}
	}
	return false
}

// Actionable は中以上の指摘を持つパッケージ数。
func Actionable(rep *model.Report) int {
	n := 0
	for _, r := range rep.Results {
		if r.MaxSeverity() >= model.SevMedium {
			n++
		}
	}
	return n
}

// JSON は機械可読な結果を書く。
func JSON(w io.Writer, rep *model.Report, failAt model.Severity) error {
	type finding struct {
		Severity string `json:"severity"`
		Code     string `json:"code"`
		Message  string `json:"message"`
	}
	type result struct {
		Ecosystem       string         `json:"ecosystem"`
		Name            string         `json:"name"`
		Version         string         `json:"version,omitempty"`
		Direct          bool           `json:"direct"`
		Dev             bool           `json:"dev,omitempty"`
		Manifests       []string       `json:"manifests,omitempty"`
		Repository      string         `json:"repository,omitempty"`
		RepositoryURL   string         `json:"repositoryUrl,omitempty"`
		Provenance      string         `json:"provenance,omitempty"`
		Stars           int            `json:"stars,omitempty"`
		Score           *float64       `json:"score,omitempty"`
		ScorecardDate   string         `json:"scorecardDate,omitempty"`
		Maintained      *int           `json:"maintained,omitempty"`
		MaintainedWhy   string         `json:"maintainedReason,omitempty"`
		Licenses        []string       `json:"licenses,omitempty"`
		LicenseSummary  string         `json:"licenseSummary,omitempty"`
		Advisories      []string       `json:"advisories,omitempty"`
		LatestVersion   string         `json:"latestVersion,omitempty"`
		PublishedAt     string         `json:"publishedAt,omitempty"`
		LatestPublished string         `json:"latestPublishedAt,omitempty"`
		Checks          map[string]int `json:"checks,omitempty"`
		Findings        []finding      `json:"findings,omitempty"`
		LookupError     string         `json:"lookupError,omitempty"`
	}
	counts := countFindings(rep)
	out := struct {
		ScannedAt string         `json:"scannedAt"`
		Roots     []string       `json:"roots,omitempty"`
		Manifests int            `json:"manifests"`
		Packages  int            `json:"packages"`
		Findings  map[string]int `json:"findings"`
		Failed    bool           `json:"failed"`
		Warnings  []string       `json:"warnings,omitempty"`
		Results   []result       `json:"results"`
	}{
		ScannedAt: rep.ScannedAt.UTC().Format(time.RFC3339),
		Roots:     rep.Roots,
		Manifests: rep.Manifests,
		Packages:  len(rep.Results),
		Findings: map[string]int{
			"high":   counts[model.SevHigh],
			"medium": counts[model.SevMedium],
			"low":    counts[model.SevLow],
		},
		Failed:   ShouldFail(rep, failAt),
		Warnings: rep.Warnings,
	}
	for _, r := range rep.Results {
		jr := result{
			Ecosystem:      r.Ecosystem,
			Name:           r.Name,
			Version:        r.Version,
			Direct:         r.Direct,
			Dev:            r.Dev,
			Manifests:      r.Manifests,
			Repository:     r.Repository,
			RepositoryURL:  repo.URL(r.Repository),
			Provenance:     r.Provenance,
			Stars:          r.Stars,
			Score:          r.Score,
			Maintained:     r.Maintained,
			MaintainedWhy:  r.MaintainedReason,
			Licenses:       r.Licenses,
			LicenseSummary: r.LicenseSummary,
			Advisories:     r.Advisories,
			LatestVersion:  r.LatestVersion,
			Checks:         r.Checks,
			LookupError:    r.LookupError,
		}
		if !r.ScoreDate.IsZero() {
			jr.ScorecardDate = r.ScoreDate.UTC().Format("2006-01-02")
		}
		if !r.PublishedAt.IsZero() {
			jr.PublishedAt = r.PublishedAt.UTC().Format(time.RFC3339)
		}
		if !r.LatestPublished.IsZero() {
			jr.LatestPublished = r.LatestPublished.UTC().Format(time.RFC3339)
		}
		for _, f := range r.Findings {
			jr.Findings = append(jr.Findings, finding{Severity: f.Severity.String(), Code: f.Code, Message: f.Message})
		}
		out.Results = append(out.Results, jr)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}
