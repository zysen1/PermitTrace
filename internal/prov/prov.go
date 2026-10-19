// Package prov attributes a permission request to the untrusted context that
// most likely induced it. Scoring is lexical overlap, imperative phrasing, and
// recency. Judge is optional; MockJudge is deterministic and is the default.
package prov

import (
	"regexp"
	"strings"
	"unicode"
)

// Segment is one piece of context. Trust is "trusted" or "untrusted".
// Source is user, system, file:<path>, web:<domain>, mcp:<server>, issue:<id>, or skill:<path>.
type Segment struct {
	Source  string
	Trust   string
	Text    string
	Locator string
	Index   int
}

// Hit is a scored segment.
type Hit struct {
	Segment    Segment
	Score      float64
	Lexical    float64
	Imperative float64
	Temporal   float64
	Judge      float64
}

// Judge scores a segment against the request text. Implementations must be
// safe to call offline. A nil judge skips this term.
type Judge interface {
	Score(segmentText, requestText string) float64
}

// MockJudge adds a small deterministic bonus when the segment and the request
// share a multi-word command fragment such as "npm run" or "git commit".
type MockJudge struct{}

func (MockJudge) Score(segmentText, requestText string) float64 {
	seg := strings.ToLower(segmentText)
	req := strings.ToLower(requestText)
	frags := []string{"npm run", "git commit", "git push", "bash(*)", "domain:*"}
	for _, f := range frags {
		if strings.Contains(seg, f) && strings.Contains(req, f) {
			return 1
		}
	}
	return 0
}

var imperatives = []string{
	"always allow",
	"always run",
	"add to allow",
	"add to the allow",
	"don't ask",
	"do not ask",
	"dont ask",
	"skip permissions",
	"skip permission",
	"dangerously-skip-permissions",
	"settings.json",
	"settings.local.json",
	"permanently allow",
	"permanent allow",
	"from now on",
	"never prompt",
	"without prompting",
	"without asking",
	"without further confirmation",
	"auto-approve",
	"yolo",
	"allow-rule",
	"allow rule",
	"permission rule",
	"don't ask again",
	"do not ask again",
}

var tokenRE = regexp.MustCompile(`[a-z0-9_./:~*-]+`)

var stop = map[string]bool{
	"the": true, "and": true, "for": true, "with": true, "this": true,
	"that": true, "from": true, "into": true, "your": true, "please": true,
	"before": true, "after": true, "then": true, "than": true, "just": true,
	"will": true, "can": true, "you": true, "are": true, "was": true,
}

// Attribute ranks segments. Only untrusted segments are returned; trusted
// user text is intent, not an induction source. k is the maximum length.
func Attribute(segments []Segment, requestText string, judge Judge, k int) []Hit {
	if k <= 0 {
		k = 3
	}
	var hits []Hit
	n := len(segments)
	for i, s := range segments {
		if s.Trust == "trusted" || strings.HasPrefix(s.Source, "user") || s.Source == "system" || s.Source == "assistant" {
			continue
		}
		if s.Trust == "" && !untrustedSource(s.Source) {
			continue
		}
		lex := lexical(s.Text, requestText)
		imp := imperative(s.Text)
		temp := 0.0
		if n > 1 {
			temp = float64(i) / float64(n-1)
		}
		j := 0.0
		if judge != nil {
			j = judge.Score(s.Text, requestText)
		}
		score := 0.55*lex + 0.30*imp + 0.15*temp + 0.10*j
		if score > 1 {
			score = 1
		}
		s.Index = i
		hits = append(hits, Hit{Segment: s, Score: score, Lexical: lex, Imperative: imp, Temporal: temp, Judge: j})
	}
	for i := 0; i < len(hits); i++ {
		for j := i + 1; j < len(hits); j++ {
			if hits[j].Score > hits[i].Score {
				hits[i], hits[j] = hits[j], hits[i]
			}
		}
	}
	if len(hits) > k {
		hits = hits[:k]
	}
	return hits
}

func untrustedSource(source string) bool {
	for _, p := range []string{"file:", "web:", "mcp:", "issue:", "skill:", "pr:"} {
		if strings.HasPrefix(source, p) {
			return true
		}
	}
	return false
}

func lexical(segment, request string) float64 {
	req := tokens(request)
	if len(req) == 0 {
		return 0
	}
	seg := map[string]bool{}
	for _, t := range tokens(segment) {
		seg[t] = true
	}
	inter := 0
	for _, t := range req {
		if seg[t] {
			inter++
		}
	}
	score := float64(inter) / float64(len(req))
	lowSeg := strings.ToLower(segment)
	lowReq := strings.ToLower(request)
	// Exact rule or command substring is stronger than a bag of words.
	for _, piece := range strings.FieldsFunc(lowReq, func(r rune) bool { return r == '\n' || r == ',' }) {
		piece = strings.TrimSpace(piece)
		if len(piece) >= 6 && strings.Contains(lowSeg, piece) {
			if score < 0.85 {
				score = 0.85
			}
		}
	}
	if score > 1 {
		return 1
	}
	return score
}

func tokens(s string) []string {
	s = strings.ToLower(s)
	raw := tokenRE.FindAllString(s, -1)
	var out []string
	seen := map[string]bool{}
	for _, t := range raw {
		t = strings.Trim(t, ".:")
		if len(t) < 2 || stop[t] || seen[t] {
			continue
		}
		if strings.IndexFunc(t, unicode.IsLetter) < 0 && strings.IndexFunc(t, unicode.IsDigit) < 0 {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

func imperative(text string) float64 {
	low := strings.ToLower(text)
	score := 0.0
	for _, p := range imperatives {
		if strings.Contains(low, p) {
			score += 0.34
		}
	}
	if strings.Contains(text, "Bash(") || strings.Contains(text, "WebFetch(") || strings.Contains(text, "Read(") {
		score += 0.40
	}
	if score > 1 {
		return 1
	}
	return score
}
