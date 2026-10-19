// Package synth searches the allow-rule lattice for the narrowest rules that
// cover the observed task commands and match no dangerous witness.
// Lattice, narrowest first: one exact command per task command, then a single
// shared prefix wildcard. A bare tool wildcard is never synthesized.
package synth

import (
	"strings"

	"github.com/zysen1/PermitTrace/internal/indirect"
	"github.com/zysen1/PermitTrace/internal/radius"
	"github.com/zysen1/PermitTrace/internal/rules"
)

// Bash returns exact Bash rules for task commands when those rules have no
// blast-radius witness. It falls back to one shared prefix rule only when
// there are more exact commands than Claude Code saves from a single approval
// (5) and the prefix itself is safe.
func Bash(task []string, idx *indirect.Index) []rules.Rule {
	task = unique(task)
	if len(task) == 0 {
		return nil
	}
	var exact []rules.Rule
	for _, cmd := range task {
		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}
		r := rules.Rule{Tool: "Bash", Spec: cmd, Behavior: "allow", Raw: "Bash(" + cmd + ")"}
		exact = append(exact, r)
	}
	if len(exact) > 0 && len(exact) <= 5 && safe(exact, idx, task) {
		return exact
	}
	if p, ok := sharedPrefix(task); ok {
		r := rules.Rule{Tool: "Bash", Spec: p, Behavior: "allow", Raw: "Bash(" + p + ")"}
		if safe([]rules.Rule{r}, idx, task) && covers([]rules.Rule{r}, task) {
			return []rules.Rule{r}
		}
	}
	if len(exact) > 5 && safe(exact, idx, task) {
		return exact
	}
	return nil
}

// Read returns one Read rule per path when the set is at most five and none
// of the rules match a secret witness path. The paths should already be the
// concrete files the task read.
func Read(paths []string) []rules.Rule {
	paths = unique(paths)
	if len(paths) == 0 || len(paths) > 5 {
		return nil
	}
	var out []rules.Rule
	for _, p := range paths {
		spec := p
		r := rules.Rule{Tool: "Read", Spec: spec, Behavior: "allow", Raw: "Read(" + spec + ")"}
		out = append(out, r)
	}
	if radius.MaxWeight(radius.Blast(out, nil, nil)) > 0 {
		return nil
	}
	return out
}

// WebFetch returns a domain rule for the host. A wildcard domain is not synthesized.
func WebFetch(rawURL string) []rules.Rule {
	host := hostOnly(rawURL)
	if host == "" || strings.Contains(host, "*") {
		return nil
	}
	spec := "domain:" + host
	r := rules.Rule{Tool: "WebFetch", Spec: spec, Behavior: "allow", Raw: "WebFetch(" + spec + ")"}
	return []rules.Rule{r}
}

func safe(rs []rules.Rule, idx *indirect.Index, task []string) bool {
	if !covers(rs, task) {
		return false
	}
	ws := radius.Blast(rs, idx, task)
	return len(ws) == 0
}

func covers(rs []rules.Rule, task []string) bool {
	for _, cmd := range task {
		ok := false
		for _, r := range rs {
			if r.AllowsBash(cmd) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func sharedPrefix(cmds []string) (string, bool) {
	if len(cmds) < 2 {
		return "", false
	}
	var words [][]string
	for _, c := range cmds {
		w := strings.Fields(c)
		if len(w) == 0 {
			return "", false
		}
		words = append(words, w)
	}
	n := len(words[0])
	for _, w := range words[1:] {
		if len(w) < n {
			n = len(w)
		}
	}
	var common []string
	for i := 0; i < n; i++ {
		same := true
		for _, w := range words[1:] {
			if w[i] != words[0][i] {
				same = false
				break
			}
		}
		if !same {
			break
		}
		common = append(common, words[0][i])
	}
	if len(common) == 0 {
		return "", false
	}
	// A prefix rule is "words *", and it must be strictly shorter than every command
	// so it is a real generalization. Require at least the program name.
	return strings.Join(common, " ") + " *", true
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func hostOnly(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	raw = strings.TrimSuffix(raw, ".")
	if i := strings.LastIndex(raw, "@"); i >= 0 {
		raw = raw[i+1:]
	}
	if i := strings.Index(raw, ":"); i >= 0 {
		raw = raw[:i]
	}
	return strings.ToLower(raw)
}

// IsNarrower reports whether synth is a strict subset of proposed on the
// finite universe of task commands, corpus commands, and repo entrypoints.
func IsNarrower(proposed, narrowed []rules.Rule, idx *indirect.Index, task []string) bool {
	if len(narrowed) == 0 || len(proposed) == 0 {
		return false
	}
	if sameSpecs(proposed, narrowed) {
		return false
	}
	universe := append([]string{}, task...)
	corpus, err := radius.LoadCorpus()
	if err == nil {
		for _, ex := range corpus {
			universe = append(universe, ex.Command)
		}
	}
	if idx != nil {
		for name := range idx.Scripts {
			universe = append(universe, "npm run "+name)
		}
		for name := range idx.Targets {
			universe = append(universe, "make "+name)
		}
		for name := range idx.Recipes {
			universe = append(universe, "just "+name)
		}
		for name := range idx.Aliases {
			universe = append(universe, "git "+name)
		}
	}
	extra := false
	for _, cmd := range universe {
		p := allowsAny(proposed, cmd)
		n := allowsAny(narrowed, cmd)
		if n && !p {
			return false
		}
		if p && !n {
			extra = true
		}
	}
	return extra
}

func allowsAny(rs []rules.Rule, cmd string) bool {
	for _, r := range rs {
		if strings.EqualFold(r.Tool, "Bash") || strings.EqualFold(r.Tool, "PowerShell") {
			if r.AllowsBash(cmd) {
				return true
			}
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
