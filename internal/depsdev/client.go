// Package depsdev は deps.dev API v3 からパッケージ版、最新版、OpenSSF Scorecard を取る。
package depsdev

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nozo-moto/dephealth/internal/repo"
)

const defaultBase = "https://api.deps.dev"

// ErrNotFound はパッケージやプロジェクトが deps.dev に無いことを示す。
var ErrNotFound = errors.New("deps.dev に見つかりません")

type Check struct {
	Score  int
	Reason string
}

type Version struct {
	System              string
	Name                string
	Version             string
	PublishedAt         time.Time
	Licenses            []string
	Advisories          []string
	Deprecated          bool
	DeprecatedReason    string
	ProjectID           string
	Provenance          string
	ProjectStatus       string
	ProjectStatusReason string
}

type Package struct {
	DefaultVersion   string
	DefaultPublished time.Time
}

type Project struct {
	ID        string
	License   string
	Stars     int
	Score     *float64
	ScoreDate time.Time
	Checks    map[string]Check
}

type Client struct {
	base  string
	http  *http.Client
	sem   chan struct{}
	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	v   any
	err error
}

func New(base string, concurrency int) *Client {
	if base == "" {
		base = defaultBase
	}
	if concurrency < 1 {
		concurrency = 8
	}
	return &Client{
		base:  strings.TrimRight(base, "/"),
		http:  &http.Client{Timeout: 45 * time.Second},
		sem:   make(chan struct{}, concurrency),
		cache: map[string]cacheEntry{},
	}
}

func (c *Client) Version(ctx context.Context, system, name, version string) (*Version, error) {
	system = strings.ToLower(system)
	key := "v\x00" + system + "\x00" + name + "\x00" + version
	if v, err, ok := c.cached(key); ok {
		if err != nil {
			return nil, err
		}
		return v.(*Version), nil
	}
	got, err := c.fetchVersion(ctx, system, name, version)
	if err != nil && errors.Is(err, ErrNotFound) && system == "pypi" {
		norm := pep503(name)
		if norm != name {
			got, err = c.fetchVersion(ctx, system, norm, version)
		}
	}
	if err == nil || errors.Is(err, ErrNotFound) {
		c.store(key, got, err)
	}
	return got, err
}

func (c *Client) Package(ctx context.Context, system, name string) (*Package, error) {
	system = strings.ToLower(system)
	key := "p\x00" + system + "\x00" + name
	if v, err, ok := c.cached(key); ok {
		if err != nil {
			return nil, err
		}
		return v.(*Package), nil
	}
	got, err := c.fetchPackage(ctx, system, name)
	if err != nil && errors.Is(err, ErrNotFound) && system == "pypi" {
		norm := pep503(name)
		if norm != name {
			got, err = c.fetchPackage(ctx, system, norm)
		}
	}
	if err == nil || errors.Is(err, ErrNotFound) {
		c.store(key, got, err)
	}
	return got, err
}

func (c *Client) Project(ctx context.Context, id string) (*Project, error) {
	key := "r\x00" + id
	if v, err, ok := c.cached(key); ok {
		if err != nil {
			return nil, err
		}
		return v.(*Project), nil
	}
	got, err := c.fetchProject(ctx, id)
	if err == nil || errors.Is(err, ErrNotFound) {
		c.store(key, got, err)
	}
	return got, err
}

func (c *Client) cached(key string) (any, error, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cache[key]
	if !ok {
		return nil, nil, false
	}
	return e.v, e.err, true
}

func (c *Client) store(key string, v any, err error) {
	c.mu.Lock()
	c.cache[key] = cacheEntry{v: v, err: err}
	c.mu.Unlock()
}

func (c *Client) fetchVersion(ctx context.Context, system, name, version string) (*Version, error) {
	path := "/v3/systems/" + url.PathEscape(system) + "/packages/" + url.PathEscape(name) + "/versions/" + url.PathEscape(version)
	var raw versionJSON
	if err := c.get(ctx, path, &raw); err != nil {
		return nil, err
	}
	return raw.toVersion(), nil
}

func (c *Client) fetchPackage(ctx context.Context, system, name string) (*Package, error) {
	path := "/v3/systems/" + url.PathEscape(system) + "/packages/" + url.PathEscape(name)
	var raw packageJSON
	if err := c.get(ctx, path, &raw); err != nil {
		return nil, err
	}
	pkg := &Package{}
	for _, v := range raw.Versions {
		if v.IsDefault {
			pkg.DefaultVersion = v.VersionKey.Version
			pkg.DefaultPublished = parseTime(v.PublishedAt)
			break
		}
	}
	return pkg, nil
}

func (c *Client) fetchProject(ctx context.Context, id string) (*Project, error) {
	path := "/v3/projects/" + url.PathEscape(id)
	var raw projectJSON
	if err := c.get(ctx, path, &raw); err != nil {
		return nil, err
	}
	return raw.toProject(id), nil
}

func (c *Client) get(ctx context.Context, path string, dest any) error {
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 300 * time.Millisecond):
			}
		}
		err := c.getOnce(ctx, path, dest)
		if err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		last = err
		var se *statusError
		if errors.As(err, &se) && !se.retryable() {
			return err
		}
	}
	if last == nil {
		last = errors.New("deps.dev への照会に失敗しました")
	}
	return last
}

func (c *Client) getOnce(ctx context.Context, path string, dest any) error {
	select {
	case c.sem <- struct{}{}:
		defer func() { <-c.sem }()
	case <-ctx.Done():
		return ctx.Err()
	}
	u, err := url.Parse(c.base + path)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "dephealth")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 180 {
			msg = msg[:180]
		}
		return &statusError{code: resp.StatusCode, msg: msg}
	}
	if err := json.Unmarshal(body, dest); err != nil {
		return fmt.Errorf("deps.dev の応答を解釈できません: %w", err)
	}
	return nil
}

type statusError struct {
	code int
	msg  string
}

func (e *statusError) Error() string {
	if e.msg == "" {
		return fmt.Sprintf("deps.dev が HTTP %d を返しました", e.code)
	}
	return fmt.Sprintf("deps.dev が HTTP %d を返しました: %s", e.code, e.msg)
}

func (e *statusError) retryable() bool {
	return e.code == 429 || e.code >= 500
}

func pep503(name string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(name) {
		if r == '-' || r == '_' || r == '.' {
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
			continue
		}
		prevDash = false
		b.WriteRune(r)
	}
	return strings.Trim(b.String(), "-")
}

type versionJSON struct {
	VersionKey struct {
		System  string `json:"system"`
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"versionKey"`
	PublishedAt      string   `json:"publishedAt"`
	IsDeprecated     bool     `json:"isDeprecated"`
	DeprecatedReason string   `json:"deprecatedReason"`
	Licenses         []string `json:"licenses"`
	AdvisoryKeys     []struct {
		ID string `json:"id"`
	} `json:"advisoryKeys"`
	Links []struct {
		Label string `json:"label"`
		URL   string `json:"url"`
	} `json:"links"`
	SLSA []struct {
		SourceRepository string `json:"sourceRepository"`
		Verified         bool   `json:"verified"`
	} `json:"slsaProvenances"`
	Attestations []struct {
		SourceRepository string `json:"sourceRepository"`
		Verified         bool   `json:"verified"`
	} `json:"attestations"`
	Related []struct {
		ProjectKey struct {
			ID string `json:"id"`
		} `json:"projectKey"`
		Provenance string `json:"relationProvenance"`
		Type       string `json:"relationType"`
	} `json:"relatedProjects"`
	ProjectStatus *struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	} `json:"projectStatus"`
}

func (raw versionJSON) toVersion() *Version {
	v := &Version{
		System:           raw.VersionKey.System,
		Name:             raw.VersionKey.Name,
		Version:          raw.VersionKey.Version,
		PublishedAt:      parseTime(raw.PublishedAt),
		Licenses:         raw.Licenses,
		Deprecated:       raw.IsDeprecated,
		DeprecatedReason: raw.DeprecatedReason,
	}
	for _, a := range raw.AdvisoryKeys {
		if a.ID != "" {
			v.Advisories = append(v.Advisories, a.ID)
		}
	}
	if raw.ProjectStatus != nil {
		v.ProjectStatus = raw.ProjectStatus.Status
		v.ProjectStatusReason = raw.ProjectStatus.Reason
	}
	id, prov := selectRepo(raw)
	v.ProjectID = id
	v.Provenance = prov
	return v
}

func selectRepo(raw versionJSON) (string, string) {
	bestID, bestProv, bestRank := "", "", 0
	for _, rel := range raw.Related {
		if rel.Type != "SOURCE_REPO" {
			continue
		}
		rank := provenanceRank(rel.Provenance)
		if rank > bestRank {
			bestID = rel.ProjectKey.ID
			bestProv = rel.Provenance
			bestRank = rank
		}
	}
	if bestRank >= provenanceRank("SLSA_ATTESTATION") && bestID != "" {
		return bestID, bestProv
	}
	for _, a := range raw.Attestations {
		if !a.Verified || a.SourceRepository == "" {
			continue
		}
		if id := repo.ProjectID(a.SourceRepository); id != "" {
			return id, "SLSA_ATTESTATION"
		}
	}
	for _, s := range raw.SLSA {
		if !s.Verified || s.SourceRepository == "" {
			continue
		}
		if id := repo.ProjectID(s.SourceRepository); id != "" {
			return id, "SLSA_ATTESTATION"
		}
	}
	if bestID != "" {
		return bestID, bestProv
	}
	for _, a := range raw.Attestations {
		if id := repo.ProjectID(a.SourceRepository); id != "" {
			return id, "UNVERIFIED_METADATA"
		}
	}
	for _, l := range raw.Links {
		if l.Label != "SOURCE_REPO" {
			continue
		}
		if id := repo.ProjectID(l.URL); id != "" {
			return id, "LINK"
		}
		if id := repo.GooglesourceMirror(l.URL); id != "" {
			return id, "GO_MIRROR"
		}
	}
	return "", ""
}

func provenanceRank(p string) int {
	switch p {
	case "SLSA_ATTESTATION", "PYPI_PUBLISH_ATTESTATION", "RUBYGEMS_PUBLISH_ATTESTATION":
		return 40
	case "GO_ORIGIN":
		return 30
	case "UNVERIFIED_METADATA":
		return 10
	default:
		return 0
	}
}

type packageJSON struct {
	Versions []struct {
		VersionKey struct {
			Version string `json:"version"`
		} `json:"versionKey"`
		PublishedAt string `json:"publishedAt"`
		IsDefault   bool   `json:"isDefault"`
	} `json:"versions"`
}

type projectJSON struct {
	ProjectKey struct {
		ID string `json:"id"`
	} `json:"projectKey"`
	License    string `json:"license"`
	StarsCount int    `json:"starsCount"`
	Scorecard  *struct {
		Date         string  `json:"date"`
		OverallScore float64 `json:"overallScore"`
		Checks       []struct {
			Name   string  `json:"name"`
			Score  float64 `json:"score"`
			Reason string  `json:"reason"`
		} `json:"checks"`
	} `json:"scorecard"`
}

func (raw projectJSON) toProject(fallback string) *Project {
	id := raw.ProjectKey.ID
	if id == "" {
		id = fallback
	}
	p := &Project{
		ID:      id,
		License: raw.License,
		Stars:   raw.StarsCount,
		Checks:  map[string]Check{},
	}
	if raw.Scorecard == nil || len(raw.Scorecard.Checks) == 0 {
		return p
	}
	score := raw.Scorecard.OverallScore
	p.Score = &score
	p.ScoreDate = parseTime(raw.Scorecard.Date)
	for _, c := range raw.Scorecard.Checks {
		if c.Score < 0 {
			continue
		}
		p.Checks[c.Name] = Check{Score: int(c.Score), Reason: c.Reason}
	}
	return p
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t
	}
	return time.Time{}
}
