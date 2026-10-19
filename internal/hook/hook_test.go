package hook

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zysen1/PermitTrace/internal/engine"
	"github.com/zysen1/PermitTrace/internal/rules"
)

func TestPermissionRequestNarrowShape(t *testing.T) {
	res := engine.Result{
		Action:      "narrow",
		Reason:      "narrowed",
		Capability:  1,
		Destination: "session",
		Synthesized: []rules.Rule{rules.ParseRule("Bash(npm run test)")},
		Proposed:    []rules.Rule{rules.ParseRule("Bash(npm run *)")},
	}
	raw, err := json.Marshal(Build("PermissionRequest", res))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	hso := got["hookSpecificOutput"].(map[string]any)
	if hso["hookEventName"] != "PermissionRequest" {
		t.Fatalf("%v", hso)
	}
	dec := hso["decision"].(map[string]any)
	if dec["behavior"] != "allow" {
		t.Fatalf("behavior %v", dec["behavior"])
	}
	ups := dec["updatedPermissions"].([]any)
	up := ups[0].(map[string]any)
	if up["type"] != "addRules" || up["destination"] != "session" || up["behavior"] != "allow" {
		t.Fatalf("update %#v", up)
	}
	ruleset := up["rules"].([]any)
	rule := ruleset[0].(map[string]any)
	if rule["toolName"] != "Bash" || rule["ruleContent"] != "npm run test" {
		t.Fatalf("rule %#v", rule)
	}
	if _, ok := hso["permissionDecision"]; ok {
		t.Fatal("PermissionRequest must not use permissionDecision")
	}
}

func TestPreToolUseUsesPermissionDecision(t *testing.T) {
	res := engine.Result{Action: "deny", Reason: "no"}
	out := Build("PreToolUse", res)
	if out.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatal(out.HookSpecificOutput.PermissionDecision)
	}
	if out.HookSpecificOutput.Decision != nil {
		t.Fatal("PreToolUse must not use decision.behavior")
	}
	ask := Build("PermissionRequest", engine.Result{Action: "ask", Reason: "look"})
	if ask.HookSpecificOutput != nil {
		t.Fatal("ask must leave the prompt in place by omitting decision")
	}
	if !strings.Contains(ask.SystemMessage, "look") {
		t.Fatal(ask.SystemMessage)
	}
}

func TestRunRoundTrip(t *testing.T) {
	in := `{
	  "hook_event_name": "PermissionRequest",
	  "cwd": "/repo",
	  "tool_name": "Bash",
	  "tool_input": {"command": "npm test"},
	  "permission_suggestions": [{
	    "type": "addRules",
	    "behavior": "allow",
	    "destination": "localSettings",
	    "rules": [{"toolName": "Bash", "ruleContent": "npm test"}]
	  }]
	}`
	var buf bytes.Buffer
	err := Run(strings.NewReader(in), &buf, func(in engine.Input) engine.Result {
		if in.Command != "npm test" || in.Cwd != "/repo" {
			t.Fatalf("input %#v", in)
		}
		if len(in.Suggestions) != 1 || in.Suggestions[0].Rules[0].Spec != "npm test" {
			t.Fatalf("suggestions %#v", in.Suggestions)
		}
		return engine.Result{Action: "allow", Capability: 0, Proposed: in.Suggestions[0].Rules, Destination: "localSettings"}
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"behavior":"allow"`)) {
		t.Fatalf("stdout %s", buf.String())
	}
}
