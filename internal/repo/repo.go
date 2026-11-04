// Package repo は GitHub / GitLab / Bitbucket の URL を deps.dev の project id に揃える。
package repo

import (
	"net/url"
	"strings"
)

// ProjectID はリポジトリ URL や git 指定を github.com/owner/repo の形にする。
// 解釈できないときは空文字を返す。
func ProjectID(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	raw = strings.TrimPrefix(raw, "git+")
	raw = strings.TrimSuffix(raw, "/")
	if i := strings.Index(raw, "#"); i >= 0 && !strings.Contains(raw[:i], " ") {
		raw = raw[:i]
	}
	raw = strings.TrimSuffix(raw, ".git")

	if strings.HasPrefix(raw, "git@") {
		rest := strings.TrimPrefix(raw, "git@")
		host, path, ok := strings.Cut(rest, ":")
		if !ok {
			return ""
		}
		raw = "https://" + host + "/" + strings.TrimPrefix(path, "/")
	}
	if strings.HasPrefix(raw, "github:") {
		raw = "https://github.com/" + strings.TrimPrefix(raw, "github:")
	} else if strings.HasPrefix(raw, "gitlab:") {
		raw = "https://gitlab.com/" + strings.TrimPrefix(raw, "gitlab:")
	} else if strings.HasPrefix(raw, "bitbucket:") {
		raw = "https://bitbucket.org/" + strings.TrimPrefix(raw, "bitbucket:")
	}

	if !strings.Contains(raw, "://") {
		switch {
		case strings.HasPrefix(raw, "github.com/"),
			strings.HasPrefix(raw, "gitlab.com/"),
			strings.HasPrefix(raw, "bitbucket.org/"):
			raw = "https://" + raw
		default:
			return ""
		}
	}

	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	host = strings.TrimPrefix(host, "www.")
	path := strings.Trim(u.Path, "/")
	path = strings.TrimSuffix(path, ".git")
	if path == "" {
		return ""
	}
	parts := strings.Split(path, "/")
	switch host {
	case "github.com", "bitbucket.org":
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return ""
		}
		return host + "/" + parts[0] + "/" + parts[1]
	case "gitlab.com":
		var b []string
		for _, p := range parts {
			if p == "-" {
				break
			}
			if p != "" {
				b = append(b, p)
			}
		}
		if len(b) < 2 {
			return ""
		}
		return host + "/" + strings.Join(b, "/")
	default:
		return ""
	}
}

// URL は project id をブラウザで開ける URL にする。
func URL(id string) string {
	if id == "" {
		return ""
	}
	if strings.Contains(id, "://") {
		return id
	}
	return "https://" + id
}

// InferGo はモジュールパスからリポジトリを推定する。
// 2 番目の戻り値は INFERRED または GO_MIRROR。推定できないときは空。
func InferGo(modulePath string) (string, string) {
	if id := ProjectID(modulePath); id != "" {
		return id, "INFERRED"
	}
	if strings.HasPrefix(modulePath, "golang.org/x/") {
		name := strings.TrimPrefix(modulePath, "golang.org/x/")
		name = strings.Split(name, "/")[0]
		if name != "" {
			return "github.com/golang/" + name, "GO_MIRROR"
		}
	}
	if strings.HasPrefix(modulePath, "gopkg.in/") {
		if id := gopkgIn(modulePath); id != "" {
			return id, "INFERRED"
		}
	}
	return "", ""
}

// GooglesourceMirror は go.googlesource.com/mod を公式ミラー github.com/golang/mod にする。
// Scorecard は GitHub ミラー側にしか無い。
func GooglesourceMirror(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "git+")
	if i := strings.Index(raw, "#"); i >= 0 {
		raw = raw[:i]
	}
	if !strings.Contains(raw, "://") {
		if strings.HasPrefix(raw, "go.googlesource.com/") {
			raw = "https://" + raw
		} else {
			return ""
		}
	}
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Hostname(), "go.googlesource.com") {
		return ""
	}
	name := strings.Trim(strings.TrimSuffix(u.Path, ".git"), "/")
	if name == "" {
		return ""
	}
	name = strings.Split(name, "/")[0]
	if name == "" {
		return ""
	}
	return "github.com/golang/" + name
}

func gopkgIn(modulePath string) string {
	rest := strings.TrimPrefix(modulePath, "gopkg.in/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || parts[0] == "" {
		return ""
	}
	strip := func(s string) string {
		if i := strings.LastIndex(s, ".v"); i > 0 {
			return s[:i]
		}
		return s
	}
	if strings.Contains(parts[0], ".v") {
		name := strip(parts[0])
		if name == "" {
			return ""
		}
		return "github.com/go-" + name + "/" + name
	}
	if len(parts) >= 2 {
		repo := strip(parts[1])
		if repo == "" {
			return ""
		}
		return "github.com/" + parts[0] + "/" + repo
	}
	return ""
}
