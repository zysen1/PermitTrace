// Package rules matches Claude Code and OpenCode permission rules.
//
// Claude Code rule syntax follows the permissions reference as fetched on
// 2026-10-19 (https://code.claude.com/docs/en/permissions). Bash wildcards
// use *, a trailing " *" also matches the bare command when it is the only
// wildcard, and a trailing :* is the same as a trailing " *". :* is only
// special at the end of the pattern. Compound allow matching requires every
// top-level subcommand to match; deny and ask match if any simple command
// matches, including commands nested in substitutions.
package rules

import (
	"net/url"
	"path"
	"strings"

	"github.com/zysen1/PermitTrace/internal/shell"
)

// Rule is one Tool or Tool(specifier) permission rule.
type Rule struct {
	Tool     string
	Spec     string // empty means the whole tool; "*" is Bash(*)
	Behavior string // allow, deny, ask
	Raw      string
}

// ParseRule parses "Bash(npm run *)", "WebFetch(domain:example.com)", "Read(./.env)", or "Bash".
// Parentheses inside the specifier are literal, so the specifier runs from the
// first "(" to the last ")".
func ParseRule(raw string) Rule {
	raw = strings.TrimSpace(raw)
	r := Rule{Raw: raw}
	open := strings.IndexByte(raw, '(')
	if open < 0 || !strings.HasSuffix(raw, ")") {
		r.Tool = raw
		return r
	}
	r.Tool = raw[:open]
	r.Spec = raw[open+1 : len(raw)-1]
	return r
}

func (r Rule) String() string {
	if r.Raw != "" {
		return r.Raw
	}
	if r.Spec == "" {
		return r.Tool
	}
	return r.Tool + "(" + r.Spec + ")"
}

// AllowsBash reports whether an allow rule permits the full command string.
// Unparseable commands are not approved by a wildcard, matching the reference
// note on a trailing "&&".
func (r Rule) AllowsBash(command string) bool {
	if !r.isBash() {
		return false
	}
	if r.wholeTool() {
		return true
	}
	a := shell.Parse(command)
	if !a.OK {
		return false
	}
	if len(a.Subcommands) == 0 {
		return false
	}
	for _, s := range a.Subcommands {
		if !matchBashPattern(r.Spec, s.Normalized) {
			return false
		}
	}
	return true
}

// MatchesBashDeny reports whether a deny or ask rule matches any simple
// command, including nested ones, after stripping leading assignments.
func (r Rule) MatchesBashDeny(command string) bool {
	if !r.isBash() {
		return false
	}
	if r.wholeTool() {
		return true
	}
	a := shell.Parse(command)
	if !a.OK {
		return matchBashPattern(r.Spec, strings.TrimSpace(command))
	}
	cmds := a.Calls
	if len(cmds) == 0 {
		cmds = a.Subcommands
	}
	for _, s := range cmds {
		target := s.DenyText
		if target == "" {
			target = s.Normalized
		}
		if matchBashPattern(r.Spec, target) {
			return true
		}
	}
	return false
}

func (r Rule) isBash() bool {
	return strings.EqualFold(r.Tool, "Bash") || strings.EqualFold(r.Tool, "PowerShell")
}

func (r Rule) wholeTool() bool {
	return r.Spec == "" || r.Spec == "*"
}

// matchBashPattern implements the wildcard table in the permissions reference.
func matchBashPattern(pattern, command string) bool {
	pattern = strings.TrimSpace(pattern)
	command = strings.TrimSpace(command)
	pattern = rewriteColonStar(pattern)
	if !strings.Contains(pattern, "*") {
		return pattern == command
	}
	if prefix, ok := barePrefix(pattern); ok && command == prefix {
		return true
	}
	return wildcardMatch(pattern, command)
}

// rewriteColonStar rewrites a trailing :* suffix into " *". The reference
// says :* is only recognized at the end; "git:* push" keeps a literal colon.
func rewriteColonStar(pattern string) string {
	if strings.HasSuffix(pattern, ":*") {
		return strings.TrimSuffix(pattern, ":*") + " *"
	}
	return pattern
}

// barePrefix is the text before a single trailing " *".
func barePrefix(pattern string) (string, bool) {
	if strings.Count(pattern, "*") != 1 || !strings.HasSuffix(pattern, " *") {
		return "", false
	}
	return strings.TrimSuffix(pattern, " *"), true
}

// wildcardMatch is a full-string match where each * consumes any text,
// including spaces and empty.
func wildcardMatch(pattern, command string) bool {
	parts := strings.Split(pattern, "*")
	rest := command
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(rest, part)
		if idx < 0 {
			return false
		}
		if i == 0 && idx != 0 {
			return false
		}
		rest = rest[idx+len(part):]
	}
	if !strings.HasSuffix(pattern, "*") && rest != "" {
		return false
	}
	return true
}

// MatchWebFetch reports whether rule matches rawURL.
// Domain rules follow the reference: case-insensitive, a trailing dot is
// ignored, "*.example.com" matches subdomains but not the apex, "*" matches
// every host, and any other * does not cross a dot.
func MatchWebFetch(rule Rule, rawURL string) bool {
	if !strings.EqualFold(rule.Tool, "WebFetch") {
		return false
	}
	if rule.Spec == "" {
		return true
	}
	spec := rule.Spec
	if !strings.HasPrefix(strings.ToLower(spec), "domain:") {
		return false
	}
	pattern := strings.TrimSuffix(strings.ToLower(strings.TrimPrefix(spec, "domain:")), ".")
	host := hostOf(rawURL)
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		base := pattern[2:]
		return host != base && strings.HasSuffix(host, suffix)
	}
	pp := strings.Split(pattern, ".")
	hh := strings.Split(host, ".")
	if len(pp) != len(hh) {
		return false
	}
	for i := range pp {
		if !labelMatch(pp[i], hh[i]) {
			return false
		}
	}
	return true
}

func labelMatch(pattern, label string) bool {
	if pattern == "*" {
		return true
	}
	return wildcardMatch(pattern, label)
}

func hostOf(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return strings.ToLower(rawURL)
	}
	return strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
}

// MatchPath reports whether a Read or Edit pattern matches path.
// behavior is "allow", "deny", or "ask" and changes how a single-segment
// relative directory pattern is anchored. home and cwd are absolute paths
// with forward slashes. This covers the pattern table in the reference; it
// does not implement gitignore negation ("!") or symlink dual-checks.
func MatchPath(rule Rule, filePath, home, cwd string) bool {
	tool := strings.ToLower(rule.Tool)
	if tool != "read" && tool != "edit" {
		return false
	}
	if rule.Spec == "" || rule.Spec == "*" {
		return true
	}
	return pathMatch(rule.Spec, filePath, home, cwd, rule.Behavior)
}

func pathMatch(pattern, filePath, home, cwd, behavior string) bool {
	filePath = cleanPath(filePath)
	home = cleanPath(home)
	cwd = cleanPath(cwd)
	pat := pattern
	anchoredAnyDepth := false
	switch {
	case strings.HasPrefix(pat, "//"):
		filePath = strings.TrimPrefix(filePath, "/")
		pat = strings.TrimPrefix(pat, "//")
	case strings.HasPrefix(pat, "~/"):
		pat = strings.TrimPrefix(pat, "~/")
		if home == "" {
			return false
		}
		if !strings.HasPrefix(filePath, home) {
			return false
		}
		filePath = strings.TrimPrefix(strings.TrimPrefix(filePath, home), "/")
	case strings.HasPrefix(pat, "/"):
		pat = strings.TrimPrefix(pat, "/")
		if cwd != "" && strings.HasPrefix(filePath, cwd) {
			filePath = strings.TrimPrefix(strings.TrimPrefix(filePath, cwd), "/")
		} else if strings.HasPrefix(filePath, "/") {
			// compare as relative to cwd failed
			return false
		}
	default:
		pat = strings.TrimPrefix(pat, "./")
		if cwd != "" && strings.HasPrefix(filePath, cwd) {
			filePath = strings.TrimPrefix(strings.TrimPrefix(filePath, cwd), "/")
		}
		filePath = strings.TrimPrefix(filePath, "/")
		if !strings.Contains(pat, "/") {
			anchoredAnyDepth = true
		}
		if (behavior == "deny" || behavior == "ask" || behavior == "") && singleSegmentGlobstar(pat) {
			anchoredAnyDepth = true
		}
	}
	if globMatch(pat, filePath) {
		return true
	}
	if anchoredAnyDepth && globMatch("**/"+pat, filePath) {
		return true
	}
	return false
}

func singleSegmentGlobstar(pat string) bool {
	// "src/**" or "secrets/**" — one path segment followed by /**
	body, ok := strings.CutSuffix(pat, "/**")
	return ok && body != "" && !strings.Contains(body, "/") && !strings.ContainsAny(body, "*?")
}

func globMatch(pattern, filePath string) bool {
	pattern = path.Clean(pattern)
	filePath = path.Clean(filePath)
	if pattern == "." {
		pattern = ""
	}
	return globSeg(strings.Split(pattern, "/"), strings.Split(filePath, "/"))
}

func globSeg(pat, segs []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			// ** consumes zero or more segments, and also collapses duplicate **
			for len(pat) > 0 && pat[0] == "**" {
				pat = pat[1:]
			}
			if len(pat) == 0 {
				return true
			}
			for i := 0; i <= len(segs); i++ {
				if globSeg(pat, segs[i:]) {
					return true
				}
			}
			return false
		}
		if len(segs) == 0 {
			return false
		}
		if !segMatch(pat[0], segs[0]) {
			return false
		}
		pat = pat[1:]
		segs = segs[1:]
	}
	return len(segs) == 0
}

func segMatch(pattern, seg string) bool {
	if pattern == "*" {
		return true
	}
	// * and ? within one segment
	return wildcardQuestion(pattern, seg)
}

func wildcardQuestion(pattern, s string) bool {
	for {
		if pattern == "" {
			return s == ""
		}
		if pattern[0] == '*' {
			pattern = pattern[1:]
			if pattern == "" {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if wildcardQuestion(pattern, s[i:]) {
					return true
				}
			}
			return false
		}
		if s == "" {
			return false
		}
		if pattern[0] != '?' && pattern[0] != s[0] {
			return false
		}
		pattern = pattern[1:]
		s = s[1:]
	}
}

func cleanPath(p string) string {
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, "\\", "/")
	if strings.HasPrefix(p, "~/") {
		return p
	}
	if !strings.HasPrefix(p, "/") && !strings.Contains(p, ":") {
		return path.Clean(p)
	}
	// keep absolute
	c := path.Clean(p)
	if strings.HasPrefix(p, "/") && !strings.HasPrefix(c, "/") {
		return "/" + c
	}
	return c
}
