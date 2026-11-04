package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/nozo-moto/dephealth/internal/assess"
	"github.com/nozo-moto/dephealth/internal/ghissue"
	"github.com/nozo-moto/dephealth/internal/license"
	"github.com/nozo-moto/dephealth/internal/model"
	"github.com/nozo-moto/dephealth/internal/report"
	"github.com/nozo-moto/dephealth/internal/scan"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stderr, usage)
		return 2
	}
	if args[0] != "scan" {
		fmt.Fprintf(stderr, "未知のコマンド %q\n\n%s", args[0], usage)
		return 2
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOut := fs.Bool("json", false, "")
	direct := fs.Bool("direct", false, "")
	verbose := fs.Bool("verbose", false, "")
	all := fs.Bool("all", false, "")
	minScore := fs.Float64("min-score", 5, "")
	minMaintained := fs.Int("min-maintained", 5, "")
	staleDays := fs.Int("stale-days", 365, "")
	failOn := fs.String("fail-on", "medium", "")
	concurrency := fs.Int("concurrency", 8, "")
	timeout := fs.Duration("timeout", 10*time.Minute, "")
	depsURL := fs.String("depsdev-url", "", "")
	ghRef := fs.String("github-issue", "", "")
	ghToken := fs.String("github-token", "", "")
	ghTitle := fs.String("github-issue-title", "", "")
	ghAPI := fs.String("github-api", "", "")
	licensePolicy := fs.String("license-policy", "default", "")
	allowLic := fs.String("allow-license", "", "")
	denyLic := fs.String("deny-license", "", "")
	weak := fs.String("license-weak", "warn", "")
	ignore := fs.String("ignore", "", "")
	parsed, err := reorderArgs(args[1:])
	if err != nil {
		fmt.Fprintf(stderr, "%s\n\n%s", err, usage)
		return 2
	}
	if err := fs.Parse(parsed); err != nil {
		fmt.Fprintf(stderr, "%s\n\n%s", err, usage)
		return 2
	}
	failAt, err := model.ParseFailOn(*failOn)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	switch *weak {
	case "ignore", "warn", "fail":
	default:
		fmt.Fprintln(stderr, "--license-weak は ignore, warn, fail のいずれかです")
		return 2
	}
	switch *licensePolicy {
	case "default", "off":
	default:
		fmt.Fprintln(stderr, "--license-policy は default または off です")
		return 2
	}
	roots := fs.Args()
	if len(roots) == 0 {
		roots = []string{"."}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	rep, err := scan.Run(ctx, roots, scan.Option{
		DirectOnly:  *direct,
		Concurrency: *concurrency,
		DepsDevURL:  *depsURL,
		Ignore:      splitList(*ignore),
		Assess: assess.Options{
			MinScore:      *minScore,
			MinMaintained: *minMaintained,
			StaleDays:     *staleDays,
			License: license.Policy{
				Enabled: *licensePolicy != "off",
				Allow:   license.ParseList(*allowLic),
				Deny:    license.ParseList(*denyLic),
				Weak:    *weak,
			},
		},
	})
	if err != nil {
		fmt.Fprintf(stderr, "走査に失敗しました: %s\n", err)
		return 2
	}
	if rep.Manifests == 0 {
		fmt.Fprintln(stderr, "依存マニフェストが見つかりません。go.mod、package.json、Cargo.toml、pyproject.toml、requirements.txt、Gemfile.lock などを指してください。")
		return 2
	}
	view := report.View{
		Verbose:       *verbose,
		All:           *all,
		MinScore:      *minScore,
		MinMaintained: *minMaintained,
		FailAt:        failAt,
	}
	if *jsonOut {
		if err := report.JSON(stdout, rep, failAt); err != nil {
			fmt.Fprintf(stderr, "JSON の出力に失敗しました: %s\n", err)
			return 2
		}
	} else {
		report.Text(stdout, rep, view)
	}

	code := 0
	if report.ShouldFail(rep, failAt) {
		code = 1
	}
	if strings.TrimSpace(*ghRef) != "" {
		if err := publish(ctx, stderr, *ghRef, *ghToken, *ghTitle, *ghAPI, rep, view); err != nil {
			fmt.Fprintf(stderr, "Issue への書き込みに失敗しました: %s\n", err)
			return 2
		}
	}
	return code
}

// reorderArgs はパスより後ろに書いたフラグも flag が読めるように並べ替える。
func reorderArgs(args []string) ([]string, error) {
	boolFlags := map[string]bool{
		"json": true, "direct": true, "verbose": true, "all": true,
		"h": true, "help": true,
	}
	var flags, paths []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			paths = append(paths, args[i+1:]...)
			break
		}
		if a == "-" || !strings.HasPrefix(a, "-") {
			paths = append(paths, a)
			continue
		}
		name := strings.TrimLeft(a, "-")
		if name == "" {
			return nil, fmt.Errorf("不正なフラグ %q", a)
		}
		flags = append(flags, a)
		if strings.Contains(name, "=") || boolFlags[name] {
			continue
		}
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
			return nil, fmt.Errorf("%s には値が必要です", a)
		}
		i++
		flags = append(flags, args[i])
	}
	return append(flags, paths...), nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func publish(ctx context.Context, stderr io.Writer, refRaw, token, title, api string, rep *model.Report, view report.View) error {
	ref, err := ghissue.ParseRef(refRaw)
	if err != nil {
		return err
	}
	tok, err := ghissue.Token(token)
	if err != nil {
		return err
	}
	if api == "" {
		api = os.Getenv("GITHUB_API_URL")
	}
	if strings.TrimSpace(title) == "" {
		date := rep.ScannedAt.In(time.FixedZone("JST", 9*60*60)).Format("2006-01-02")
		n := report.Actionable(rep)
		if n == 0 {
			title = fmt.Sprintf("dephealth: 要対応なし (%s)", date)
		} else {
			title = fmt.Sprintf("dephealth: 要対応 %d 件 (%s)", n, date)
		}
	}
	u, err := ghissue.Publish(ctx, api, tok, ref, title, report.Markdown(rep, view))
	if err != nil {
		return err
	}
	if ref.Number == 0 {
		fmt.Fprintf(stderr, "Issue を作成しました: %s\n", u)
	} else {
		fmt.Fprintf(stderr, "Issue にサマリを書きました: %s\n", u)
	}
	return nil
}

const usage = `dephealth は依存パッケージのソースリポジトリを特定し、OpenSSF Scorecard、更新の遅れ、ライセンスを評価します。

使い方:
  dephealth scan [ディレクトリまたはマニフェスト...]

対応するマニフェスト:
  go.mod
  package.json と package-lock.json / pnpm-lock.yaml / yarn.lock
  Cargo.toml / Cargo.lock
  pyproject.toml / requirements.txt / poetry.lock / uv.lock
  Gemfile / Gemfile.lock

Go は go.mod の require（indirect を含む）を見ます。
npm / Cargo / Ruby はロックファイルがあれば推移的依存も含みます。
Python は poetry.lock か uv.lock があるとき推移的依存を含み、無いときは宣言された直接依存だけです。
  peerDependencies、ローカル path、file:、replace のローカルパスは見ません。
  golang.org/x/... は github.com/golang/... のミラーとして Scorecard を見ます。
  gopkg.in は gopkg.in の規約で GitHub リポジトリを推定します。

オプション:
  --json                         JSON を標準出力へ出す
  --direct                       直接依存だけを評価する
  --ignore pattern,pattern       無視するパス。root からの相対パスか区間名の glob。
                                 例: --ignore "docs,playground/**"。.worktrees は既定で無視する。
  --all                          指摘が無いパッケージも表示する
  --verbose                      低リスクの指摘も表示する
  --min-score float              Scorecard 総合スコアの閾値（既定 5、0 で無効）
  --min-maintained int           Maintained スコアの閾値（既定 5、0 で無効）
  --stale-days int               最新版よりこの日数以上古い版を指摘する（既定 365、0 で無効）
  --fail-on none|low|medium|high この重大度以上で終了コード 1（既定 medium）
  --concurrency int              deps.dev への同時リクエスト数（既定 8）
  --timeout duration             全体の制限時間（既定 10m）
  --license-policy default|off   ライセンス分類（既定 default）
  --license-weak ignore|warn|fail
                                 弱いコピーレフトの扱い（既定 warn。低リスクの指摘）
  --allow-license SPDX,SPDX      このファミリーは問題なしにする（例: GPL-3.0,MPL-2.0）
  --deny-license SPDX,SPDX       このファミリーを常に高リスクにする
  --github-issue target          サマリを GitHub Issue に書く
  --github-issue-title string    新規 Issue のタイトル
  --github-token string          トークン。無ければ GITHUB_TOKEN、GH_TOKEN、gh auth token
  --github-api url               GitHub API のベース URL（既定 https://api.github.com）
  --depsdev-url url              deps.dev API のベース URL

--github-issue の形式:
  owner/repo#123
  https://github.com/owner/repo/issues/123
      その Issue にコメントする。dephealth のコメントが既にあれば更新する。
  owner/repo
  https://github.com/owner/repo
      新しい Issue を作る。

終了コード:
  0  閾値以上の指摘がない
  1  指摘がある
  2  使い方、走査、または Issue への書き込みに失敗した

ライセンスの既定:
  寛容（MIT, Apache-2.0, BSD など）は指摘しない。
  MIT OR GPL のように選択できる場合は寛容な側を採用する。
  強いコピーレフト（GPL, AGPL など）は中。
  弱いコピーレフト（LGPL, MPL, EPL など）は低。
  ソース利用に制限があるもの（BUSL, SSPL など）と、ライセンス未記載・non-standard は高。
  分類できない SPDX は中。
  deps.dev がライセンスを複数返したときは関係が不明なので、すべてを満たすものとして扱う。

Scorecard の見方:
  Dangerous-Workflow の失敗は、GitHub Actions からリポジトリを書き換えられうるパターン。
  Binary-Artifacts の失敗は、中身を追えないバイナリがリポジトリに含まれている。
  Token-Permissions が広いものは件数に出すが、多くのリポジトリが該当するためパッケージごとの失敗にはしない。
  Maintained が 0 は、アーカイブか長期の無更新。

例:
  dephealth scan .
  dephealth scan ./service ./web --direct
  dephealth scan . --json --fail-on high
  dephealth scan . --deny-license WTFPL --allow-license GPL-2.0
  dephealth scan . --github-issue myorg/myrepo#120
  dephealth scan . --github-issue myorg/security-reviews
`
