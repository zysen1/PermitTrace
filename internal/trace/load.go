// Package trace reads the PermitTrace JSONL schema and, as a supplement, Claude
// Code session transcripts. Hook decisions use stdin as the source of truth;
// a transcript is only extra context and may lag the live session.
package trace

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"

	"github.com/zysen1/PermitTrace/internal/engine"
)

// Load reads path. Unknown lines are skipped. A missing file is an error.
func Load(path string) ([]engine.Segment, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var out []engine.Segment
	for sc.Scan() {
		line := bytesTrim(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		seg, ok := parseLine(line)
		if ok {
			out = append(out, seg)
		}
	}
	return out, sc.Err()
}

func parseLine(line []byte) (engine.Segment, bool) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(line, &probe); err != nil {
		return engine.Segment{}, false
	}
	if _, ok := probe["source"]; ok {
		return parseNative(line)
	}
	if _, ok := probe["message"]; ok {
		return parseClaude(line)
	}
	return engine.Segment{}, false
}

type native struct {
	Role                  string          `json:"role"`
	Source                string          `json:"source"`
	Trust                 string          `json:"trust"`
	Text                  string          `json:"text"`
	Locator               string          `json:"locator"`
	Tool                  string          `json:"tool"`
	ToolInput             map[string]any  `json:"tool_input"`
	PermissionSuggestions json.RawMessage `json:"permission_suggestions"`
}

func parseNative(line []byte) (engine.Segment, bool) {
	var n native
	if err := json.Unmarshal(line, &n); err != nil {
		return engine.Segment{}, false
	}
	s := engine.Segment{
		Source: n.Source, Trust: n.Trust, Text: n.Text, Locator: n.Locator, Tool: n.Tool,
	}
	if n.Tool == "" {
		s.Tool = n.Role
	}
	if n.ToolInput != nil {
		if c, ok := n.ToolInput["command"].(string); ok {
			s.Command = c
		}
		if p, ok := n.ToolInput["file_path"].(string); ok {
			s.FilePath = p
		}
	}
	if s.Trust == "" {
		s.Trust = defaultTrust(s.Source)
	}
	return s, s.Text != "" || s.Command != ""
}

func parseClaude(line []byte) (engine.Segment, bool) {
	var row struct {
		Type    string `json:"type"`
		Message struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"message"`
	}
	if err := json.Unmarshal(line, &row); err != nil {
		return engine.Segment{}, false
	}
	text := claudeContent(row.Message.Content)
	if text == "" {
		return engine.Segment{}, false
	}
	trust := "trusted"
	source := row.Message.Role
	if row.Type == "user" && strings.Contains(text, "tool_result") {
		// Claude Code stores tool results on user turns. File contents in those
		// results are untrusted context, not a fresh human instruction.
		source = "file:transcript"
		trust = "untrusted"
	}
	if source == "" {
		source = row.Type
	}
	if source == "user" || source == "assistant" || source == "system" {
		trust = "trusted"
	}
	return engine.Segment{Source: source, Trust: trust, Text: text}, true
}

func claudeContent(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var blocks []struct {
		Type  string `json:"type"`
		Text  string `json:"text"`
		Name  string `json:"name"`
		Input struct {
			Command  string `json:"command"`
			FilePath string `json:"file_path"`
		} `json:"input"`
	}
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return ""
	}
	var b strings.Builder
	for _, bl := range blocks {
		if bl.Text != "" {
			b.WriteString(bl.Text)
			b.WriteByte('\n')
		}
		if bl.Input.Command != "" {
			b.WriteString(bl.Input.Command)
			b.WriteByte('\n')
		}
	}
	return strings.TrimSpace(b.String())
}

func defaultTrust(source string) string {
	switch {
	case strings.HasPrefix(source, "file:"), strings.HasPrefix(source, "web:"),
		strings.HasPrefix(source, "mcp:"), strings.HasPrefix(source, "issue:"),
		strings.HasPrefix(source, "pr:"), strings.HasPrefix(source, "skill:"):
		return "untrusted"
	default:
		return "trusted"
	}
}

func bytesTrim(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}
