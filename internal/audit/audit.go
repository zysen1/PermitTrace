// Package audit statically checks Claude Code settings and OpenCode configs
// for allow rules whose blast radius includes a dangerous witness.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/zysen1/PermitTrace/internal/indirect"
	"github.com/zysen1/PermitTrace/internal/radius"
	"github.com/zysen1/PermitTrace/internal/rules"
)

// Finding is one allow rule that auto-approves a dangerous command.
type Finding struct {
	File         string   `json:"file"`
	Rule         string   `json:"rule"`
	Capabilities []string `json:"capabilities"`
	Examples     []string `json:"examples"`
	Harness      string   `json:"harness"`
}

// Scan walks root for .claude/settings*.json and opencode.json.
func Scan(root string) ([]Finding, error) {
	if root == "" {
		root = "."
	}
	idx, err := indirect.Load(root)
	if err != nil {
		return nil, err
	}
	var findings []Finding
	for _, rel := range []string{
		filepath.Join(".claude", "settings.json"),
		filepath.Join(".claude", "settings.local.json"),
	} {
		path := filepath.Join(root, rel)
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		findings = append(findings, claudeFindings(rel, b, idx)...)
	}
	for _, rel := range []string{"opencode.json", filepath.Join(".opencode", "opencode.json")} {
		path := filepath.Join(root, rel)
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		got, err := openCodeFindings(rel, b, idx)
		if err != nil {
			return findings, err
		}
		findings = append(findings, got...)
	}
	return findings, nil
}

type claudeSettings struct {
	Permissions struct {
		Allow []string `json:"allow"`
		Deny  []string `json:"deny"`
		Ask   []string `json:"ask"`
	} `json:"permissions"`
}

func claudeFindings(file string, b []byte, idx *indirect.Index) []Finding {
	var doc claudeSettings
	if err := json.Unmarshal(b, &doc); err != nil {
		return []Finding{{File: file, Rule: "(unreadable settings)", Harness: "claude-code", Examples: []string{err.Error()}}}
	}
	var deny []rules.Rule
	for _, raw := range doc.Permissions.Deny {
		r := rules.ParseRule(raw)
		r.Behavior = "deny"
		deny = append(deny, r)
	}
	var out []Finding
	for _, raw := range doc.Permissions.Allow {
		r := rules.ParseRule(raw)
		r.Behavior = "allow"
		ws := radius.Blast([]rules.Rule{r}, idx, nil)
		if len(ws) == 0 {
			continue
		}
		// A deny rule that matches the same command text stops the allow.
		var examples []string
		caps := map[string]bool{}
		for _, w := range ws {
			cmd := w.Command
			if denied(deny, cmd) {
				continue
			}
			caps[w.Capability] = true
			if len(examples) < 3 {
				ex := w.Command
				if w.Detail != "" {
					ex += " → " + one(w.Detail)
				}
				examples = append(examples, ex+" ["+w.Capability+"]")
			}
		}
		if len(examples) == 0 {
			continue
		}
		out = append(out, Finding{
			File: file, Rule: r.String(), Harness: "claude-code",
			Capabilities: keys(caps), Examples: examples,
		})
	}
	return out
}

func denied(deny []rules.Rule, cmd string) bool {
	for _, d := range deny {
		if strings.EqualFold(d.Tool, "Bash") && d.MatchesBashDeny(cmd) {
			return true
		}
	}
	return false
}

func openCodeFindings(file string, b []byte, idx *indirect.Index) ([]Finding, error) {
	oc, err := rules.ParseOpenCode(b)
	if err != nil {
		return []Finding{{File: file, Rule: "(unreadable opencode.json)", Harness: "opencode", Examples: []string{err.Error()}}}, nil
	}
	// Representative commands: corpus plus repo entrypoints. Last matching rule wins.
	corpus, err := radius.LoadCorpus()
	if err != nil {
		return nil, err
	}
	type hit struct {
		cmd  string
		caps []string
	}
	var dangerous []hit
	for _, ex := range corpus {
		if rules.DecideOpenCode(oc, "bash", ex.Command) == "allow" {
			dangerous = append(dangerous, hit{ex.Command, ex.Capabilities})
		}
	}
	if idx != nil {
		for name, sc := range idx.Scripts {
			cmd := "npm run " + name
			if rules.DecideOpenCode(oc, "bash", cmd) != "allow" {
				continue
			}
			caps := radius.Classify(sc.Body)
			if len(caps) > 0 {
				dangerous = append(dangerous, hit{cmd + " → " + one(sc.Body), caps})
			}
		}
	}
	if len(dangerous) == 0 {
		return nil, nil
	}
	// Group under the allow patterns that matched, so the finding names a rule.
	var allows []rules.OpenCodeRule
	for _, r := range oc {
		if r.Permission == "bash" && r.Action == "allow" {
			allows = append(allows, r)
		}
	}
	if len(allows) == 0 {
		return nil, nil
	}
	var out []Finding
	for _, a := range allows {
		var examples []string
		caps := map[string]bool{}
		for _, d := range dangerous {
			cmd := d.cmd
			if i := strings.Index(cmd, " → "); i >= 0 {
				cmd = cmd[:i]
			}
			if !openMatch(a.Pattern, cmd) && !openMatch(a.Pattern, d.cmd) {
				continue
			}
			for _, c := range d.caps {
				caps[c] = true
			}
			if len(examples) < 3 {
				examples = append(examples, d.cmd)
			}
		}
		if len(examples) == 0 {
			continue
		}
		out = append(out, Finding{
			File: file, Rule: "bash: " + a.Pattern + " = allow", Harness: "opencode",
			Capabilities: keys(caps), Examples: examples,
		})
	}
	return out, nil
}

func openMatch(pattern, input string) bool {
	// Reuse Decide by a one-rule set. "*" matches everything.
	return rules.DecideOpenCode([]rules.OpenCodeRule{{Permission: "bash", Pattern: pattern, Action: "allow"}}, "bash", input) == "allow"
}

func keys(m map[string]bool) []string {
	var out []string
	for _, k := range []string{"arbitrary_exec", "privilege_escalation", "read_secrets", "persistence", "write_outside", "network_exfil"} {
		if m[k] {
			out = append(out, k)
		}
	}
	return out
}

func one(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}
