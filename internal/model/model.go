// Package model は dephealth がマニフェストからレポートまで持ち回る型を置く。
package model

import "time"

// Severity は指摘の重大度。数値が大きいほど重い。
type Severity int

const (
	SevNone Severity = iota
	SevLow
	SevMedium
	SevHigh
	// SevNever は --fail-on none のとき、どの指摘でも失敗させない閾値。
	SevNever
)

func (s Severity) Label() string {
	switch s {
	case SevLow:
		return "低"
	case SevMedium:
		return "中"
	case SevHigh:
		return "高"
	default:
		return ""
	}
}

func (s Severity) String() string {
	switch s {
	case SevLow:
		return "low"
	case SevMedium:
		return "medium"
	case SevHigh:
		return "high"
	case SevNever:
		return "none"
	default:
		return "none"
	}
}

// ParseFailOn は --fail-on の値を、失敗にする最小重大度へ変える。
func ParseFailOn(s string) (Severity, error) {
	switch s {
	case "none", "off":
		return SevNever, nil
	case "low":
		return SevLow, nil
	case "medium":
		return SevMedium, nil
	case "high":
		return SevHigh, nil
	default:
		return 0, errFailOn
	}
}

type failOnError struct{}

func (failOnError) Error() string {
	return "--fail-on は none, low, medium, high のいずれかです"
}

var errFailOn failOnError

const (
	CodeAdvisory          = "advisory"
	CodeDeprecated        = "deprecated"
	CodeDangerousWorkflow = "dangerous-workflow"
	CodeBinary            = "binary-artifacts"
	CodeVulnerabilities   = "vulnerabilities"
	CodeUnmaintained      = "unmaintained"
	CodeLowMaintained     = "low-maintained"
	CodeLowScore          = "low-score"
	CodeStale             = "stale"
	CodeNoRepo            = "no-repo"
	CodeNoScorecard       = "no-scorecard"
	CodeLicense           = "license"
	CodeLicenseMismatch   = "license-mismatch"
	CodeUnpinned          = "unpinned"
	CodeLookup            = "lookup-failed"
	CodeProjectStatus     = "project-status"
)

// Dep はマニフェストから取り出した依存ひとつ。
type Dep struct {
	Ecosystem    string
	Name         string
	Version      string
	Direct       bool
	Dev          bool
	Manifest     string
	RepoHint     string
	SkipRegistry bool
}

// Finding はパッケージに対する指摘ひとつ。
type Finding struct {
	Severity Severity
	Code     string
	Message  string
}

// Result は依存ひとつを照会し、判定したあとの結果。
type Result struct {
	Ecosystem        string
	Name             string
	Version          string
	Direct           bool
	Dev              bool
	Manifests        []string
	Repository       string
	Provenance       string
	Stars            int
	Score            *float64
	ScoreDate        time.Time
	Maintained       *int
	MaintainedReason string
	Licenses         []string
	LicenseSummary   string
	Advisories       []string
	LatestVersion    string
	PublishedAt      time.Time
	LatestPublished  time.Time
	Checks           map[string]int
	Findings         []Finding
	LookupError      string
}

func (r Result) MaxSeverity() Severity {
	m := SevNone
	for _, f := range r.Findings {
		if f.Severity > m {
			m = f.Severity
		}
	}
	return m
}

// Report は 1 回の scan の結果。
type Report struct {
	ScannedAt time.Time
	Roots     []string
	Manifests int
	Warnings  []string
	Results   []Result
}
