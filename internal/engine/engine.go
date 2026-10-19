// Package engine decides allow, narrow, ask, or deny for one permission request.
//
// A single risk scalar cannot express the four outcomes, so the scalar is
// reported and the decision uses three explicit questions:
//
//  1. Is this call itself high-capability and induced by untrusted context? Deny.
//  2. Is this call safe, and is there a strictly narrower rule that still covers
//     the observed task without matching a dangerous witness? Narrow.
//  3. Is the proposed rule or this call high-capability? Ask.
//  4. Otherwise allow.
//
// Thresholds live in this file. They were chosen from the capability weights
// and the dev scenarios, and they are not revised against the held-out split.
package engine

import (
	"fmt"
	"strings"

	"github.com/zysen1/PermitTrace/internal/indirect"
	"github.com/zysen1/PermitTrace/internal/prov"
	"github.com/zysen1/PermitTrace/internal/radius"
	"github.com/zysen1/PermitTrace/internal/rules"
	"github.com/zysen1/PermitTrace/internal/synth"
)

const (
	// DenyCapability is the weight at which the current call is refused when
	// untrusted context induced it. arbitrary_exec is 1.0, read_secrets is 0.85,
	// network_exfil is 0.70, so a fetch is asked about and a pipe-to-shell is denied.
	DenyCapability = 0.80
	// DenyTrust is the attribution score required before an automatic deny.
	// Below this, a high-capability call is asked about instead of refused,
	// because lexical attribution misses paraphrases.
	DenyTrust = 0.35
	// HighCapability is the weight at which a proposed rule or call is not
	// auto-allowed. Auto-narrow only happens when the current call is below this.
	HighCapability = 0.50
)

// Segment is one transcript record. Tool commands become the task set.
type Segment struct {
	Source   string
	Trust    string
	Text     string
	Locator  string
	Tool     string
	Command  string
	FilePath string
}

// Update is one permission_suggestions entry.
type Update struct {
	Type        string
	Behavior    string
	Destination string
	Mode        string
	Rules       []rules.Rule
}

// Input is everything the decision may look at. The hook stdin is authoritative;
// transcript segments are supplementary context.
type Input struct {
	Tool        string
	Command     string
	FilePath    string
	URL         string
	Suggestions []Update
	Segments    []Segment
	Repo        *indirect.Index
	Home        string
	Cwd         string
}

// Result is the decision and the evidence behind it.
type Result struct {
	Action       string
	Reason       string
	Risk         float64
	Trust        float64
	Capability   float64
	CurrentRisk  float64
	Scope        string
	ScopeWeight  float64
	Destination  string
	Capabilities []string
	Witnesses    []radius.Witness
	Attribution  []prov.Hit
	Proposed     []rules.Rule
	Synthesized  []rules.Rule
	Task         []string
	Tool         string
	Current      string
	Interrupts   int
}

// Decide runs the pipeline.
func Decide(in Input) Result {
	proposed, scope := proposedRules(in)
	scopeW := scopeWeight(scope)
	task := taskCommands(in, proposed)
	synthRules := synthesize(in, task)
	witnesses := radius.Blast(proposed, in.Repo, taskAndCurrent(in))
	caps := radius.Capabilities(witnesses)
	capW := radius.MaxWeight(witnesses)
	curW := currentWeight(in)
	if len(proposed) == 0 && curW > capW {
		capW = curW
		caps = mergeCaps(caps, radius.Classify(in.Command))
	}
	reqText := requestText(in, proposed)
	hits := prov.Attribute(toProv(in.Segments), reqText, prov.MockJudge{}, 3)
	trust := 0.0
	if len(hits) > 0 {
		trust = hits[0].Score
	}
	narrower := false
	if len(synthRules) > 0 && len(proposed) > 0 {
		if bashRules(proposed) {
			narrower = synth.IsNarrower(proposed, synthRules, in.Repo, task)
		} else {
			narrower = specBroader(proposed, synthRules)
		}
	}
	action := "allow"
	switch {
	case curW >= DenyCapability && trust >= DenyTrust:
		action = "deny"
	case narrower && curW < HighCapability && (capW >= HighCapability || specBroader(proposed, synthRules)):
		action = "narrow"
	case capW >= HighCapability || curW >= HighCapability:
		action = "ask"
	}
	dest := in.scopeDestination(scope, trust, action)
	res := Result{
		Action:       action,
		Risk:         capW * (0.25 + 0.75*trust) * scopeW,
		Trust:        trust,
		Capability:   capW,
		CurrentRisk:  curW,
		Scope:        scope,
		ScopeWeight:  scopeW,
		Destination:  dest,
		Capabilities: caps,
		Witnesses:    trimWitnesses(witnesses, 8),
		Attribution:  hits,
		Proposed:     proposed,
		Synthesized:  synthRules,
		Task:         task,
		Tool:         in.Tool,
		Current:      currentLabel(in),
		Interrupts:   interrupts(action),
	}
	res.Reason = explain(res)
	return res
}

func (in Input) scopeDestination(scope string, trust float64, action string) string {
	if action != "narrow" && action != "allow" {
		return ""
	}
	if action == "narrow" && trust >= DenyTrust {
		// Untrusted inducement must not outlive the session.
		return "session"
	}
	switch scope {
	case "userSettings", "projectSettings":
		if action == "narrow" {
			return "localSettings"
		}
		return scope
	case "":
		return "session"
	default:
		return scope
	}
}

func interrupts(action string) int {
	if action == "ask" {
		return 1
	}
	return 0
}

func proposedRules(in Input) ([]rules.Rule, string) {
	var out []rules.Rule
	scope := "session"
	rank := map[string]int{"session": 1, "localSettings": 2, "projectSettings": 3, "userSettings": 4}
	best := 0
	for _, u := range in.Suggestions {
		if u.Destination != "" && rank[u.Destination] > best {
			best = rank[u.Destination]
			scope = u.Destination
		}
		switch u.Type {
		case "addRules", "replaceRules", "":
			if u.Behavior != "" && u.Behavior != "allow" {
				continue
			}
			for _, r := range u.Rules {
				r.Behavior = "allow"
				if r.Tool == "" {
					r.Tool = in.Tool
				}
				if r.Raw == "" {
					r.Raw = r.String()
				}
				out = append(out, r)
			}
		case "setMode":
			if u.Mode == "bypassPermissions" || u.Mode == "dontAsk" {
				out = append(out, rules.Rule{Tool: "Bash", Spec: "*", Behavior: "allow", Raw: "Bash(*)"})
				if rank["userSettings"] > best {
					scope = "userSettings"
				}
			}
		}
	}
	if len(in.Suggestions) == 0 {
		scope = "session"
	}
	return out, scope
}

func scopeWeight(scope string) float64 {
	switch scope {
	case "userSettings":
		return 1
	case "projectSettings":
		return 0.85
	case "localSettings":
		return 0.70
	default:
		return 0.45
	}
}

func taskCommands(in Input, proposed []rules.Rule) []string {
	var cmds []string
	consider := func(cmd string) {
		cmd = strings.TrimSpace(cmd)
		if cmd == "" || !safeCommand(cmd, in.Repo) {
			return
		}
		if len(proposed) > 0 && !allowedBy(proposed, cmd) {
			return
		}
		cmds = append(cmds, cmd)
	}
	for _, s := range in.Segments {
		if strings.EqualFold(s.Tool, "Bash") || strings.EqualFold(s.Tool, "PowerShell") {
			consider(s.Command)
		}
	}
	if strings.EqualFold(in.Tool, "Bash") || strings.EqualFold(in.Tool, "PowerShell") || in.Tool == "" {
		consider(in.Command)
	}
	return unique(cmds)
}

func safeCommand(cmd string, idx *indirect.Index) bool {
	if radius.Weight(radius.Classify(cmd)) >= HighCapability {
		return false
	}
	exact := rules.Rule{Tool: "Bash", Spec: cmd, Behavior: "allow", Raw: "Bash(" + cmd + ")"}
	return radius.MaxWeight(radius.Blast([]rules.Rule{exact}, idx, []string{cmd})) < HighCapability
}

func allowedBy(rs []rules.Rule, cmd string) bool {
	for _, r := range rs {
		if strings.EqualFold(r.Tool, "Bash") || strings.EqualFold(r.Tool, "PowerShell") || r.Tool == "" {
			if r.AllowsBash(cmd) {
				return true
			}
		}
	}
	return false
}

func synthesize(in Input, task []string) []rules.Rule {
	switch strings.ToLower(in.Tool) {
	case "bash", "powershell", "":
		return synth.Bash(task, in.Repo)
	case "read", "edit":
		paths := []string{}
		if in.FilePath != "" {
			paths = append(paths, in.FilePath)
		}
		for _, s := range in.Segments {
			if s.FilePath != "" && (strings.EqualFold(s.Tool, "Read") || strings.EqualFold(s.Tool, "Edit")) {
				paths = append(paths, s.FilePath)
			}
		}
		return synth.Read(paths)
	case "webfetch":
		return synth.WebFetch(in.URL)
	default:
		return nil
	}
}

func currentWeight(in Input) float64 {
	switch strings.ToLower(in.Tool) {
	case "bash", "powershell", "":
		if strings.TrimSpace(in.Command) == "" {
			return 0
		}
		exact := rules.Rule{Tool: "Bash", Spec: in.Command, Behavior: "allow", Raw: "Bash(" + in.Command + ")"}
		w := radius.MaxWeight(radius.Blast([]rules.Rule{exact}, in.Repo, []string{in.Command}))
		if c := radius.Weight(radius.Classify(in.Command)); c > w {
			w = c
		}
		return w
	case "read", "edit":
		if secretPath(in.FilePath) {
			return radius.Weights["read_secrets"]
		}
		return 0
	case "webfetch":
		if in.URL != "" {
			return radius.Weights["network_exfil"]
		}
		return 0
	default:
		return 0
	}
}

func secretPath(p string) bool {
	l := strings.ToLower(p)
	for _, n := range []string{".ssh", "id_rsa", "id_ed25519", ".aws", "credentials", ".env", "/etc/shadow", ".npmrc", ".kube", ".gnupg", "hosts.yml"} {
		if strings.Contains(l, n) {
			return true
		}
	}
	return false
}

func taskAndCurrent(in Input) []string {
	var out []string
	if in.Command != "" {
		out = append(out, in.Command)
	}
	for _, s := range in.Segments {
		if s.Command != "" {
			out = append(out, s.Command)
		}
	}
	return out
}

func toProv(segs []Segment) []prov.Segment {
	out := make([]prov.Segment, 0, len(segs))
	for _, s := range segs {
		out = append(out, prov.Segment{Source: s.Source, Trust: s.Trust, Text: s.Text, Locator: s.Locator})
	}
	return out
}

func requestText(in Input, proposed []rules.Rule) string {
	var b strings.Builder
	for _, r := range proposed {
		b.WriteString(r.String())
		b.WriteByte('\n')
	}
	b.WriteString(in.Command)
	b.WriteByte('\n')
	b.WriteString(in.FilePath)
	b.WriteByte('\n')
	b.WriteString(in.URL)
	return b.String()
}

func bashRules(rs []rules.Rule) bool {
	for _, r := range rs {
		if strings.EqualFold(r.Tool, "Bash") || strings.EqualFold(r.Tool, "PowerShell") {
			return true
		}
	}
	return false
}

func specBroader(proposed, narrowed []rules.Rule) bool {
	if len(narrowed) == 0 || sameSpecs(proposed, narrowed) {
		return false
	}
	for _, p := range proposed {
		if p.Spec == "" || p.Spec == "*" || strings.Contains(p.Spec, "*") {
			return true
		}
	}
	return false
}

func sameSpecs(a, b []rules.Rule) bool {
	if len(a) != len(b) {
		return false
	}
	used := make([]bool, len(b))
	for _, r := range a {
		found := false
		for i := range b {
			if !used[i] && r.Tool == b[i].Tool && r.Spec == b[i].Spec {
				used[i] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func mergeCaps(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range append(a, b...) {
		if c != "" && !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func currentLabel(in Input) string {
	if in.Command != "" {
		return in.Command
	}
	if in.FilePath != "" {
		return in.FilePath
	}
	return in.URL
}

func trimWitnesses(ws []radius.Witness, n int) []radius.Witness {
	if len(ws) <= n {
		return ws
	}
	// Keep the highest-weight examples.
	for i := 0; i < len(ws); i++ {
		for j := i + 1; j < len(ws); j++ {
			if radius.Weights[ws[j].Capability] > radius.Weights[ws[i].Capability] {
				ws[i], ws[j] = ws[j], ws[i]
			}
		}
	}
	return ws[:n]
}

func explain(r Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "PermitTrace decision: %s.", r.Action)
	if r.Current != "" {
		fmt.Fprintf(&b, " Current call: %s.", r.Current)
	}
	if len(r.Proposed) > 0 {
		b.WriteString(" Proposed allow rule:")
		for _, p := range r.Proposed {
			b.WriteByte(' ')
			b.WriteString(p.String())
		}
		b.WriteByte('.')
	}
	if len(r.Witnesses) > 0 {
		w := r.Witnesses[0]
		b.WriteString(" This would also unlock ")
		b.WriteString(w.Command)
		if w.Detail != "" {
			b.WriteString(" → ")
			b.WriteString(oneLine(w.Detail))
		}
		b.WriteString(" (")
		b.WriteString(w.Capability)
		b.WriteString(").")
	}
	if len(r.Attribution) > 0 && r.Attribution[0].Score >= DenyTrust {
		h := r.Attribution[0]
		loc := h.Segment.Locator
		if loc == "" {
			loc = h.Segment.Source
		}
		fmt.Fprintf(&b, " Induced by untrusted context %s (score %.2f).", loc, h.Score)
	}
	if r.Action == "narrow" && len(r.Synthesized) > 0 {
		b.WriteString(" Narrowed to")
		for _, s := range r.Synthesized {
			b.WriteByte(' ')
			b.WriteString(s.String())
		}
		fmt.Fprintf(&b, " at destination %s.", r.Destination)
	}
	if r.Action == "ask" {
		b.WriteString(" A person should decide; attribution or the capability is not clear enough to allow or refuse automatically.")
	}
	if r.Action == "deny" {
		b.WriteString(" Refused because the call's effective capability is high and the request traces to untrusted context.")
	}
	return b.String()
}

func oneLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}
