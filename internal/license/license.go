// Package license は SPDX ライセンス表現を分類する。
// 法的助言ではなく、依存を取り込む前に目を通すべきものを分けるための分類である。
package license

import (
	"fmt"
	"strings"

	"github.com/nozo-moto/dephealth/internal/model"
)

// Policy は分類をどう指摘に変えるか。
// Allow / Deny のキーは Family で正規化した SPDX ID。
// Weak は ignore / warn / fail。空なら warn。
type Policy struct {
	Enabled bool
	Allow   map[string]bool
	Deny    map[string]bool
	Weak    string
}

func (p Policy) weakMode() string {
	if p.Weak == "" {
		return "warn"
	}
	return p.Weak
}

// Verdict は 1 つのパッケージに対するライセンス判定。
type Verdict struct {
	Severity   model.Severity
	Class      string
	Summary    string
	Expression string
}

// ParseList はカンマ区切りの SPDX ID を Family の集合にする。
func ParseList(s string) map[string]bool {
	out := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out[Family(p)] = true
	}
	return out
}

// Family は GPL-3.0-only と GPL-3.0-or-later を同じ gpl-3.0 に揃える。
func Family(id string) string {
	id = strings.TrimSpace(id)
	id = strings.TrimSuffix(id, "+")
	id = strings.ToLower(id)
	id = strings.TrimSuffix(id, "-only")
	id = strings.TrimSuffix(id, "-or-later")
	return id
}

// Judge は deps.dev が返すライセンス文字列を分類する。
// 複数あるとき関係が指定されないため、すべてを満たす（AND）ものとして扱う。
func Judge(licenses []string, p Policy) Verdict {
	cleaned := make([]string, 0, len(licenses))
	for _, s := range licenses {
		s = strings.TrimSpace(s)
		if s != "" {
			cleaned = append(cleaned, s)
		}
	}
	expr := strings.Join(cleaned, " AND ")
	if !p.Enabled {
		if expr == "" {
			expr = "未記載"
		}
		return Verdict{Severity: model.SevNone, Class: "off", Summary: expr, Expression: expr}
	}
	if len(cleaned) == 0 {
		return Verdict{
			Severity:   model.SevHigh,
			Class:      "missing",
			Summary:    "未記載",
			Expression: "",
		}
	}
	n, err := parse(expr)
	if err != nil {
		return Verdict{
			Severity:   model.SevMedium,
			Class:      "unparsed",
			Summary:    "ライセンス表現を解釈できない: " + expr,
			Expression: expr,
		}
	}
	o := eval(n, p)
	return Verdict{
		Severity:   o.sev,
		Class:      o.class,
		Summary:    o.summary,
		Expression: expr,
	}
}

// NormalizeHost は GitHub などが返すライセンス名を SPDX 表現に寄せる。
// 分からないときは空文字を返し、誤った分類をしない。
func NormalizeHost(s string) string {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return ""
	}
	low := strings.ToLower(raw)
	if v, ok := hostNames[low]; ok {
		return v
	}
	if _, err := parse(raw); err == nil {
		return raw
	}
	return ""
}

type outcome struct {
	sev     model.Severity
	summary string
	class   string
}

type node interface{ isNode() }

type idNode struct {
	id        string
	plus      bool
	exception string
}

func (idNode) isNode()  {}
func (orNode) isNode()  {}
func (andNode) isNode() {}

type orNode struct{ l, r node }
type andNode struct{ l, r node }

func eval(n node, p Policy) outcome {
	switch n := n.(type) {
	case idNode:
		return judgeID(n, p)
	case orNode:
		l := eval(n.l, p)
		r := eval(n.r, p)
		best, worst := l, r
		if r.sev < l.sev {
			best, worst = r, l
		}
		if worst.sev > best.sev {
			best.summary = fmt.Sprintf("%s（代替として %s）", best.summary, worst.summary)
			best.class = best.class + "+alt"
		}
		return best
	case andNode:
		l := eval(n.l, p)
		r := eval(n.r, p)
		w := l
		if r.sev > l.sev {
			w = r
		}
		if l.sev == model.SevNone && r.sev == model.SevNone {
			w.summary = l.summary + " AND " + r.summary
			w.class = "permissive"
		} else if l.sev == r.sev && l.summary != r.summary {
			w.summary = l.summary + " AND " + r.summary
		}
		return w
	default:
		return outcome{sev: model.SevMedium, summary: "ライセンス表現を解釈できない", class: "unparsed"}
	}
}

func judgeID(n idNode, p Policy) outcome {
	disp := n.id
	if n.plus {
		disp += "+"
	}
	if n.exception != "" {
		disp += " WITH " + n.exception
	}
	fam := Family(n.id)
	if p.Deny[fam] {
		return outcome{sev: model.SevHigh, summary: disp + "（拒否リスト）", class: "deny"}
	}
	if p.Allow[fam] {
		return outcome{sev: model.SevNone, summary: disp, class: "allow"}
	}
	class, sev := classify(fam, n.exception)
	summary := disp
	switch class {
	case "strong":
		summary += "（強いコピーレフト）"
	case "weak":
		if linkingException(n.exception) {
			summary += "（リンク例外つきのコピーレフト）"
		} else {
			summary += "（弱いコピーレフト）"
		}
	case "source":
		summary += "（ソース利用に制限）"
	case "unknown":
		if fam == "non-standard" {
			summary += "（標準的な SPDX ではない）"
		} else {
			summary += "（分類できない）"
		}
	case "missing":
		summary += "（ライセンスなし）"
	}
	if class == "weak" {
		switch p.weakMode() {
		case "ignore":
			sev = model.SevNone
		case "fail":
			sev = model.SevMedium
		}
	}
	return outcome{sev: sev, summary: summary, class: class}
}

func classify(fam, exception string) (string, model.Severity) {
	switch fam {
	case "", "none", "noassertion":
		return "missing", model.SevHigh
	case "non-standard":
		return "unknown", model.SevHigh
	}
	if strings.HasPrefix(fam, "licenseref-") {
		return "unknown", model.SevMedium
	}
	if strings.HasPrefix(fam, "busl") ||
		strings.HasPrefix(fam, "sspl") ||
		strings.HasPrefix(fam, "elastic-") ||
		strings.HasPrefix(fam, "cc-by-nc") ||
		strings.HasPrefix(fam, "polyform-") ||
		strings.HasPrefix(fam, "commons-clause") {
		return "source", model.SevHigh
	}
	strong := strings.HasPrefix(fam, "agpl") ||
		strings.HasPrefix(fam, "gpl") ||
		strings.HasPrefix(fam, "eupl") ||
		strings.HasPrefix(fam, "osl") ||
		strings.HasPrefix(fam, "rpl") ||
		strings.HasPrefix(fam, "cpal") ||
		strings.HasPrefix(fam, "cc-by-sa")
	if strong {
		if linkingException(exception) {
			return "weak", model.SevLow
		}
		return "strong", model.SevMedium
	}
	if strings.HasPrefix(fam, "lgpl") ||
		strings.HasPrefix(fam, "mpl-") ||
		strings.HasPrefix(fam, "epl-") ||
		strings.HasPrefix(fam, "cddl") ||
		strings.HasPrefix(fam, "cpl-") ||
		fam == "ms-rl" {
		return "weak", model.SevLow
	}
	if permissive[fam] {
		return "permissive", model.SevNone
	}
	return "unknown", model.SevMedium
}

func linkingException(exc string) bool {
	e := strings.ToLower(exc)
	return strings.Contains(e, "classpath") ||
		strings.Contains(e, "autoconf-exception") ||
		strings.Contains(e, "gcc-linking") ||
		strings.Contains(e, "llvm-exception")
}

var permissive = map[string]bool{
	"0bsd": true, "afl-3.0": true, "apache-1.0": true, "apache-1.1": true, "apache-2.0": true,
	"artistic-2.0": true, "beerware": true, "blessing": true, "blueoak-1.0.0": true,
	"bsd-1-clause": true, "bsd-2-clause": true, "bsd-2-clause-patent": true,
	"bsd-3-clause": true, "bsd-3-clause-clear": true, "bsd-4-clause": true,
	"bsl-1.0": true, "cc-by-3.0": true, "cc-by-4.0": true, "cc0-1.0": true,
	"curl": true, "fair": true, "hpnd": true, "ijg": true, "isc": true, "libpng": true,
	"miros": true, "mit": true, "mit-0": true, "ms-pl": true, "ncsa": true, "ntp": true,
	"ofl-1.1": true, "openssl": true, "postgresql": true, "psf-2.0": true, "python-2.0": true,
	"tcl": true, "unicode-3.0": true, "unicode-dfs-2016": true, "unlicense": true,
	"upl-1.0": true, "w3c": true, "wtfpl": true, "x11": true, "zlib": true,
	"zlib-acknowledgement": true,
}

var hostNames = map[string]string{
	"mit":                "MIT",
	"mit license":        "MIT",
	"apache-2.0":         "Apache-2.0",
	"apache license 2.0": "Apache-2.0",
	"bsd-3-clause":       "BSD-3-Clause",
	"bsd 3-clause":       "BSD-3-Clause",
	"bsd 3-clause \"new\" or \"revised\" license": "BSD-3-Clause",
	"bsd-2-clause":                           "BSD-2-Clause",
	"bsd 2-clause":                           "BSD-2-Clause",
	"isc":                                    "ISC",
	"isc license":                            "ISC",
	"mpl-2.0":                                "MPL-2.0",
	"mozilla public license 2.0":             "MPL-2.0",
	"gnu general public license v2.0":        "GPL-2.0-only",
	"gnu general public license v3.0":        "GPL-3.0-only",
	"gnu lesser general public license v2.1": "LGPL-2.1-only",
	"gnu lesser general public license v3.0": "LGPL-3.0-only",
	"gnu affero general public license v3.0": "AGPL-3.0-only",
	"unlicense":                              "Unlicense",
	"the unlicense":                          "Unlicense",
	"zlib":                                   "Zlib",
	"zlib license":                           "Zlib",
	"other":                                  "",
	"none":                                   "",
	"noassertion":                            "",
}

type tokKind int

const (
	tEOF tokKind = iota
	tIdent
	tOR
	tAND
	tWITH
	tPlus
	tLParen
	tRParen
)

type token struct {
	kind tokKind
	text string
}

func tokenize(s string) ([]token, error) {
	var out []token
	for i := 0; i < len(s); {
		if s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' {
			i++
			continue
		}
		switch s[i] {
		case '(':
			out = append(out, token{tLParen, "("})
			i++
			continue
		case ')':
			out = append(out, token{tRParen, ")"})
			i++
			continue
		case '+':
			out = append(out, token{tPlus, "+"})
			i++
			continue
		}
		if isIdentStart(s[i]) {
			j := i + 1
			for j < len(s) && isIdentCont(s[j]) {
				j++
			}
			word := s[i:j]
			kind := tIdent
			switch strings.ToLower(word) {
			case "or":
				kind = tOR
			case "and":
				kind = tAND
			case "with":
				kind = tWITH
			}
			out = append(out, token{kind, word})
			i = j
			continue
		}
		return nil, fmt.Errorf("不正な文字 %q", string(s[i]))
	}
	return out, nil
}

func isIdentStart(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func isIdentCont(b byte) bool {
	return isIdentStart(b) || b == '.' || b == '-'
}

type parser struct {
	toks []token
	i    int
}

func (p *parser) peek() token {
	if p.i >= len(p.toks) {
		return token{kind: tEOF}
	}
	return p.toks[p.i]
}

func (p *parser) next() token {
	t := p.peek()
	if t.kind != tEOF {
		p.i++
	}
	return t
}

func parse(s string) (node, error) {
	toks, err := tokenize(s)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	n, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tEOF {
		return nil, fmt.Errorf("末尾に解釈できない部分がある")
	}
	return n, nil
}

func (p *parser) parseOr() (node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tOR {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = orNode{l: left, r: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (node, error) {
	left, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tAND {
		p.next()
		right, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		left = andNode{l: left, r: right}
	}
	return left, nil
}

func (p *parser) parsePrimary() (node, error) {
	t := p.peek()
	if t.kind == tLParen {
		p.next()
		n, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.next().kind != tRParen {
			return nil, fmt.Errorf("対応する括弧がない")
		}
		return n, nil
	}
	if t.kind != tIdent {
		return nil, fmt.Errorf("ライセンス ID がない")
	}
	p.next()
	n := idNode{id: t.text}
	if p.peek().kind == tPlus {
		p.next()
		n.plus = true
	}
	if p.peek().kind == tWITH {
		p.next()
		ex := p.next()
		if ex.kind != tIdent {
			return nil, fmt.Errorf("WITH の後に例外 ID がない")
		}
		n.exception = ex.text
	}
	return n, nil
}
