// Package hook speaks Claude Code's PreToolUse and PermissionRequest protocol.
//
// PreToolUse returns permissionDecision (allow, deny, ask). It cannot write
// rules. PermissionRequest returns decision.behavior allow or deny, and on
// allow may replace the suggested rule via updatedPermissions. An ask leaves
// the decision object unset so the human prompt still appears. Both events
// receive a systemMessage the user can read. Shapes follow the hooks reference
// fetched 2026-10-19: https://code.claude.com/docs/en/hooks
package hook

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/zysen1/PermitTrace/internal/engine"
	"github.com/zysen1/PermitTrace/internal/rules"
	"github.com/zysen1/PermitTrace/internal/trace"
)

// Request is the subset of hook stdin PermitTrace reads.
type Request struct {
	HookEventName         string         `json:"hook_event_name"`
	ToolName              string         `json:"tool_name"`
	ToolInput             map[string]any `json:"tool_input"`
	PermissionSuggestions []Suggestion   `json:"permission_suggestions"`
	CWD                   string         `json:"cwd"`
	TranscriptPath        string         `json:"transcript_path"`
	PermissionMode        string         `json:"permission_mode"`
}

// Suggestion is one permission update Claude Code offers in the dialog.
// permission_suggestions is not guaranteed to match the dialog rows; see the
// hooks reference. PermitTrace treats the array as the rules the agent is
// proposing, not as a pixel-perfect copy of the UI.
type Suggestion struct {
	Type        string `json:"type"`
	Behavior    string `json:"behavior"`
	Destination string `json:"destination"`
	Mode        string `json:"mode"`
	Rules       []struct {
		ToolName    string `json:"toolName"`
		RuleContent string `json:"ruleContent"`
	} `json:"rules"`
}

// Run reads one hook event and writes one JSON object to w.
func Run(r io.Reader, w io.Writer, decide func(engine.Input) engine.Result) error {
	body, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		return err
	}
	in := toInput(req)
	if req.TranscriptPath != "" {
		if segs, err := trace.Load(req.TranscriptPath); err == nil {
			in.Segments = append(segs, in.Segments...)
		}
	}
	if decide == nil {
		decide = engine.Decide
	}
	res := decide(in)
	out, err := json.Marshal(Build(req.HookEventName, res))
	if err != nil {
		return err
	}
	out = append(out, '\n')
	_, err = w.Write(out)
	return err
}

func toInput(req Request) engine.Input {
	in := engine.Input{
		Tool:     req.ToolName,
		Cwd:      req.CWD,
		Command:  str(req.ToolInput, "command"),
		FilePath: str(req.ToolInput, "file_path"),
		URL:      str(req.ToolInput, "url"),
	}
	if in.FilePath == "" {
		in.FilePath = str(req.ToolInput, "path")
	}
	for _, s := range req.PermissionSuggestions {
		u := engine.Update{Type: s.Type, Behavior: s.Behavior, Destination: s.Destination, Mode: s.Mode}
		for _, r := range s.Rules {
			u.Rules = append(u.Rules, contentRule(r.ToolName, r.RuleContent))
		}
		in.Suggestions = append(in.Suggestions, u)
	}
	return in
}

func contentRule(tool, content string) rules.Rule {
	tool = strings.TrimSpace(tool)
	content = strings.TrimSpace(content)
	if content == "" {
		return rules.Rule{Tool: tool, Behavior: "allow", Raw: tool}
	}
	if strings.HasPrefix(content, tool+"(") && strings.HasSuffix(content, ")") {
		r := rules.ParseRule(content)
		r.Behavior = "allow"
		return r
	}
	if i := strings.IndexByte(content, '('); i > 0 && strings.HasSuffix(content, ")") && !strings.Contains(content[:i], " ") {
		r := rules.ParseRule(content)
		r.Behavior = "allow"
		if r.Tool == "" {
			r.Tool = tool
		}
		return r
	}
	return rules.Rule{Tool: tool, Spec: content, Behavior: "allow", Raw: tool + "(" + content + ")"}
}

func str(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	v, _ := m[k].(string)
	return v
}

// Response is the JSON object written to stdout.
type Response struct {
	SystemMessage      string              `json:"systemMessage,omitempty"`
	HookSpecificOutput *HookSpecificOutput `json:"hookSpecificOutput,omitempty"`
}

// HookSpecificOutput is either a PreToolUse permissionDecision or a
// PermissionRequest decision object.
type HookSpecificOutput struct {
	HookEventName            string    `json:"hookEventName"`
	PermissionDecision       string    `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string    `json:"permissionDecisionReason,omitempty"`
	Decision                 *Decision `json:"decision,omitempty"`
}

// Decision is the PermissionRequest decision.
type Decision struct {
	Behavior           string   `json:"behavior"`
	Message            string   `json:"message,omitempty"`
	UpdatedPermissions []Update `json:"updatedPermissions,omitempty"`
}

// Update is one updatedPermissions entry. PermitTrace only emits addRules.
type Update struct {
	Type        string     `json:"type"`
	Behavior    string     `json:"behavior"`
	Destination string     `json:"destination"`
	Rules       []RuleSpec `json:"rules"`
}

// RuleSpec is the {toolName, ruleContent} pair from the hooks reference.
type RuleSpec struct {
	ToolName    string `json:"toolName"`
	RuleContent string `json:"ruleContent,omitempty"`
}

// Build maps an engine result onto the event's official fields.
func Build(event string, res engine.Result) Response {
	if event == "" {
		event = "PermissionRequest"
	}
	out := Response{}
	if res.Action != "allow" {
		out.SystemMessage = res.Reason
	}
	switch event {
	case "PreToolUse":
		decision := res.Action
		if decision == "narrow" {
			// PreToolUse cannot persist a rule. The call itself is safe
			// whenever we narrowed, so allow it and explain the rule to save.
			decision = "allow"
		}
		out.HookSpecificOutput = &HookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       decision,
			PermissionDecisionReason: res.Reason,
		}
	default:
		// PermissionRequest has no ask behavior. Omitting decision leaves the prompt.
		if res.Action == "ask" {
			return out
		}
		d := &Decision{}
		if res.Action == "deny" {
			d.Behavior = "deny"
			d.Message = res.Reason
		} else {
			d.Behavior = "allow"
			ruleset := res.Synthesized
			if res.Action == "allow" {
				ruleset = res.Proposed
			}
			if len(ruleset) > 0 && (res.Action == "narrow" || (res.Action == "allow" && res.Capability < engine.HighCapability)) {
				dest := res.Destination
				if dest == "" {
					dest = "session"
				}
				u := Update{Type: "addRules", Behavior: "allow", Destination: dest}
				for _, r := range ruleset {
					spec := RuleSpec{ToolName: r.Tool, RuleContent: r.Spec}
					u.Rules = append(u.Rules, spec)
				}
				d.UpdatedPermissions = []Update{u}
			}
		}
		out.HookSpecificOutput = &HookSpecificOutput{
			HookEventName: "PermissionRequest",
			Decision:      d,
		}
	}
	return out
}
