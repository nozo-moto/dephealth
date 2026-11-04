// Package ghissue は scan の Markdown を GitHub Issue に書く。
// 番号があれば、マーカー付きコメントを作り、同じマーカーがあれば更新する。
// 番号が無ければ Issue を新規作成する。
package ghissue

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unicode/utf8"
)

const Marker = "<!-- dephealth-summary -->"

const maxBody = 60000

// Ref は投稿先。Number が 0 のときは新規 Issue。
type Ref struct {
	Owner  string
	Repo   string
	Number int
}

// ParseRef は owner/repo、owner/repo#123、Issue の URL を解釈する。
func ParseRef(s string) (Ref, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, "/")
	if s == "" {
		return Ref{}, errors.New("--github-issue が空です")
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return Ref{}, fmt.Errorf("Issue の URL を解釈できません: %w", err)
		}
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) < 2 {
			return Ref{}, errors.New("Issue の URL には owner/repo が必要です")
		}
		ref := Ref{Owner: parts[0], Repo: parts[1]}
		if len(parts) >= 4 && (parts[2] == "issues" || parts[2] == "pull") && parts[3] != "" {
			n, err := strconv.Atoi(parts[3])
			if err != nil || n <= 0 {
				return Ref{}, errors.New("Issue 番号が不正です")
			}
			ref.Number = n
		}
		if err := validate(ref); err != nil {
			return Ref{}, err
		}
		return ref, nil
	}
	if left, right, ok := strings.Cut(s, "#"); ok {
		n, err := strconv.Atoi(right)
		if err != nil || n <= 0 {
			return Ref{}, errors.New("Issue 番号が不正です")
		}
		owner, repo, err := splitRepo(left)
		if err != nil {
			return Ref{}, err
		}
		return Ref{Owner: owner, Repo: repo, Number: n}, nil
	}
	owner, repo, err := splitRepo(s)
	if err != nil {
		return Ref{}, err
	}
	return Ref{Owner: owner, Repo: repo}, nil
}

func splitRepo(s string) (string, string, error) {
	owner, repo, ok := strings.Cut(strings.Trim(s, "/"), "/")
	if !ok || strings.Contains(repo, "/") {
		return "", "", errors.New("リポジトリは owner/repo の形で指定してください")
	}
	ref := Ref{Owner: owner, Repo: repo}
	if err := validate(ref); err != nil {
		return "", "", err
	}
	return owner, repo, nil
}

func validate(r Ref) error {
	if !validName(r.Owner) || !validName(r.Repo) {
		return errors.New("owner または repo に使えない文字があります")
	}
	return nil
}

func validName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

// Token はフラグ、環境変数、gh auth token の順でトークンを探す。
func Token(explicit string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		return strings.TrimSpace(explicit), nil
	}
	if v := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); v != "" {
		return v, nil
	}
	if v := strings.TrimSpace(os.Getenv("GH_TOKEN")); v != "" {
		return v, nil
	}
	out, err := exec.Command("gh", "auth", "token").Output()
	if err != nil {
		return "", errors.New("GitHub のトークンがありません。--github-token、GITHUB_TOKEN、GH_TOKEN のいずれか、または gh auth login が必要です")
	}
	tok := strings.TrimSpace(string(out))
	if tok == "" {
		return "", errors.New("gh auth token が空です")
	}
	return tok, nil
}

// Publish はサマリを書き、ブラウザ用の URL を返す。
func Publish(ctx context.Context, api, token string, ref Ref, title, body string) (string, error) {
	if api == "" {
		api = "https://api.github.com"
	}
	api = strings.TrimRight(api, "/")
	body = ensureMarker(body)
	body = truncate(body, maxBody)
	c := &http.Client{}
	if ref.Number == 0 {
		return createIssue(ctx, c, api, token, ref, title, body)
	}
	return upsertComment(ctx, c, api, token, ref, body)
}

func ensureMarker(body string) string {
	if strings.Contains(body, Marker) {
		return body
	}
	return Marker + "\n" + body
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	note := "\n\n（本文が長いため打ち切りました。完全な結果は dephealth scan --json で確認できます）\n"
	limit := max - len(note)
	if limit < len(Marker)+1 {
		limit = len(Marker) + 1
	}
	cut := s[:limit]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	if i := strings.LastIndex(cut, "\n"); i > limit/2 {
		cut = cut[:i]
	}
	return cut + note
}

type apiClient struct {
	http  *http.Client
	api   string
	token string
}

func (c *apiClient) do(ctx context.Context, method, path string, in any, out any) error {
	var buf io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		buf = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.api+path, buf)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "dephealth")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var g struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(b, &g)
		if g.Message == "" {
			g.Message = strings.TrimSpace(string(b))
		}
		if len(g.Message) > 200 {
			g.Message = g.Message[:200]
		}
		return fmt.Errorf("GitHub API が HTTP %d を返しました: %s", resp.StatusCode, g.Message)
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("GitHub API の応答を解釈できません: %w", err)
		}
	}
	return nil
}

func createIssue(ctx context.Context, httpc *http.Client, api, token string, ref Ref, title, body string) (string, error) {
	if strings.TrimSpace(title) == "" {
		title = "dephealth scan"
	}
	c := &apiClient{http: httpc, api: api, token: token}
	var resp struct {
		HTMLURL string `json:"html_url"`
	}
	err := c.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/%s/issues", ref.Owner, ref.Repo), map[string]string{
		"title": title,
		"body":  body,
	}, &resp)
	if err != nil {
		return "", err
	}
	return resp.HTMLURL, nil
}

func upsertComment(ctx context.Context, httpc *http.Client, api, token string, ref Ref, body string) (string, error) {
	c := &apiClient{http: httpc, api: api, token: token}
	var existingID int64
	for page := 1; page <= 10; page++ {
		var comments []struct {
			ID   int64  `json:"id"`
			Body string `json:"body"`
		}
		path := fmt.Sprintf("/repos/%s/%s/issues/%d/comments?per_page=100&page=%d", ref.Owner, ref.Repo, ref.Number, page)
		if err := c.do(ctx, http.MethodGet, path, nil, &comments); err != nil {
			return "", err
		}
		for _, comment := range comments {
			if strings.Contains(comment.Body, Marker) {
				existingID = comment.ID
			}
		}
		if len(comments) < 100 {
			break
		}
	}
	var resp struct {
		HTMLURL string `json:"html_url"`
	}
	if existingID != 0 {
		err := c.do(ctx, http.MethodPatch, fmt.Sprintf("/repos/%s/%s/issues/comments/%d", ref.Owner, ref.Repo, existingID), map[string]string{
			"body": body,
		}, &resp)
		return resp.HTMLURL, err
	}
	err := c.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/%s/issues/%d/comments", ref.Owner, ref.Repo, ref.Number), map[string]string{
		"body": body,
	}, &resp)
	return resp.HTMLURL, err
}
