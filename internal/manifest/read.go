package manifest

import (
	"io"
	"os"
	"strings"
)

const maxFile = 30 << 20

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFile))
	if err != nil {
		return nil, err
	}
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		b = b[3:]
	}
	return b, nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// stripLineComment は引用符の外にある # 以降を落とす。
func stripLineComment(line string) string {
	inSingle, inDouble := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\\' && inDouble && i+1 < len(line) {
			i++
			continue
		}
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if c == '#' && !inSingle && !inDouble {
			return strings.TrimSpace(line[:i])
		}
	}
	return strings.TrimSpace(line)
}

func quotedStrings(s string) []string {
	var out []string
	for i := 0; i < len(s); i++ {
		if s[i] != '"' && s[i] != '\'' {
			continue
		}
		q := s[i]
		j := i + 1
		var b strings.Builder
		for j < len(s) {
			if s[j] == '\\' && q == '"' && j+1 < len(s) {
				b.WriteByte(s[j+1])
				j += 2
				continue
			}
			if s[j] == q {
				break
			}
			b.WriteByte(s[j])
			j++
		}
		if j < len(s) && s[j] == q {
			out = append(out, b.String())
			i = j
		}
	}
	return out
}

type tomlSection struct {
	name  string
	lines []string
}

func splitTOML(data string) []tomlSection {
	var sections []tomlSection
	var cur *tomlSection
	for _, line := range strings.Split(data, "\n") {
		trim := stripLineComment(line)
		if strings.HasPrefix(trim, "[") && strings.HasSuffix(trim, "]") && !strings.Contains(trim, "=") {
			name := strings.TrimSpace(trim[1 : len(trim)-1])
			name = strings.TrimPrefix(name, "[")
			name = strings.TrimSuffix(name, "]")
			sections = append(sections, tomlSection{name: strings.TrimSpace(name)})
			cur = &sections[len(sections)-1]
			continue
		}
		if cur == nil {
			continue
		}
		cur.lines = append(cur.lines, line)
	}
	return sections
}

func keyEquals(line, key string) bool {
	trim := strings.TrimSpace(stripLineComment(line))
	if !strings.HasPrefix(trim, key) {
		return false
	}
	rest := strings.TrimSpace(trim[len(key):])
	return strings.HasPrefix(rest, "=")
}

func arrayAfterKey(lines []string, key string) []string {
	for i, line := range lines {
		if !keyEquals(line, key) {
			continue
		}
		buf := line
		if !bracketsBalanced(buf) {
			for _, extra := range lines[i+1:] {
				buf += "\n" + extra
				if bracketsBalanced(buf) {
					break
				}
			}
		}
		return quotedStrings(buf)
	}
	return nil
}

func bracketsBalanced(s string) bool {
	n := 0
	seen := false
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && inDouble {
			i++
			continue
		}
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if inSingle || inDouble {
			continue
		}
		if c == '[' {
			n++
			seen = true
		} else if c == ']' {
			n--
		}
	}
	return seen && n == 0
}

func assignments(lines []string) map[string]string {
	out := map[string]string{}
	for _, line := range lines {
		trim := stripLineComment(line)
		if trim == "" || strings.HasPrefix(trim, "[") {
			continue
		}
		name, value, ok := splitAssign(trim)
		if ok {
			out[name] = value
		}
	}
	return out
}

func splitAssign(line string) (string, string, bool) {
	inSingle, inDouble := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\'' && !inDouble {
			inSingle = !inSingle
		} else if c == '"' && !inSingle {
			inDouble = !inDouble
		}
		if c == '=' && !inSingle && !inDouble {
			name := strings.Trim(strings.TrimSpace(line[:i]), `"'`)
			if name == "" || strings.ContainsAny(name, " \t") {
				return "", "", false
			}
			return name, strings.TrimSpace(line[i+1:]), true
		}
	}
	return "", "", false
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
