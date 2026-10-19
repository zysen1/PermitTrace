package radius

import (
	_ "embed"
	"strings"
	"sync"

	"github.com/zysen1/PermitTrace/internal/indirect"
	"github.com/zysen1/PermitTrace/internal/rules"
	"gopkg.in/yaml.v3"
)

//go:embed corpus.yaml
var corpusYAML []byte

// Example is one corpus command a broad allow rule might auto-approve.
type Example struct {
	ID           string   `yaml:"id"`
	Command      string   `yaml:"command"`
	Capabilities []string `yaml:"capabilities"`
}

// Witness is one concrete thing a rule would unlock.
type Witness struct {
	Capability string `json:"capability"`
	Command    string `json:"command"`
	Detail     string `json:"detail,omitempty"`
	Source     string `json:"source"`
	Kind       string `json:"kind"` // direct, indirect
}

var (
	corpusOnce sync.Once
	corpusAll  []Example
	corpusErr  error
)

// LoadCorpus returns the embedded witness commands. The parse is cached:
// a hook invokes this on every call.
func LoadCorpus() ([]Example, error) {
	corpusOnce.Do(func() {
		corpusErr = yaml.Unmarshal(corpusYAML, &corpusAll)
	})
	return corpusAll, corpusErr
}

// Blast lists witnesses for allow rules: corpus commands the rule auto-approves,
// and repo-controlled commands the rule auto-approves whose expansion is dangerous.
func Blast(allow []rules.Rule, idx *indirect.Index, extra []string) []Witness {
	corpus, err := LoadCorpus()
	if err != nil {
		return nil
	}
	var out []Witness
	seen := map[string]bool{}
	add := func(w Witness) {
		key := w.Kind + "|" + w.Capability + "|" + w.Command + "|" + w.Detail
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, w)
	}
	for _, rule := range allow {
		if rule.Behavior != "" && rule.Behavior != "allow" {
			continue
		}
		switch strings.ToLower(rule.Tool) {
		case "bash", "powershell":
			for _, ex := range corpus {
				if !rule.AllowsBash(ex.Command) {
					continue
				}
				for _, c := range ex.Capabilities {
					add(Witness{Capability: c, Command: ex.Command, Source: "corpus:" + ex.ID, Kind: "direct"})
				}
			}
			candidates := extra
			if idx != nil {
				for name := range idx.Scripts {
					candidates = append(candidates, "npm run "+name, "npm "+name)
				}
				for name := range idx.Targets {
					candidates = append(candidates, "make "+name)
				}
				for name := range idx.Recipes {
					candidates = append(candidates, "just "+name)
				}
				for name := range idx.Aliases {
					candidates = append(candidates, "git "+name)
				}
				if len(idx.Hooks) > 0 {
					candidates = append(candidates, "git commit -am x", "pre-commit run --all-files")
				}
			}
			seenCmd := map[string]bool{}
			for _, cmd := range candidates {
				if seenCmd[cmd] || !rule.AllowsBash(cmd) {
					continue
				}
				seenCmd[cmd] = true
				for _, leaf := range expandOrSelf(idx, cmd) {
					caps := Classify(leaf.Command)
					if len(caps) == 0 {
						continue
					}
					detail := leaf.Command
					if detail == cmd {
						detail = ""
					}
					src := leaf.Source
					if src == "" || src == "command" {
						src = "expanded"
					}
					for _, c := range caps {
						add(Witness{Capability: c, Command: cmd, Detail: detail, Source: src, Kind: "indirect"})
					}
				}
			}
		case "read", "edit":
			for _, secret := range secretPaths() {
				r := rule
				r.Behavior = "allow"
				if rules.MatchPath(r, secret, "/home/ada", "/repo") {
					add(Witness{Capability: "read_secrets", Command: rule.String(), Detail: secret, Source: "path", Kind: "direct"})
				}
			}
		case "webfetch":
			if rule.Spec == "" || strings.EqualFold(rule.Spec, "domain:*") {
				add(Witness{Capability: "network_exfil", Command: rule.String(), Detail: "any host", Source: "webfetch", Kind: "direct"})
			}
		}
	}
	return out
}

func expandOrSelf(idx *indirect.Index, cmd string) []indirect.Leaf {
	if idx == nil {
		caps := Classify(cmd)
		if len(caps) == 0 {
			return nil
		}
		return []indirect.Leaf{{Command: cmd, Source: "command"}}
	}
	return idx.Expand(cmd)
}

func secretPaths() []string {
	return []string{
		"/home/ada/.ssh/id_rsa",
		"/home/ada/.aws/credentials",
		"/home/ada/.npmrc",
		"/home/ada/.kube/config",
		"/repo/.env",
		"/repo/pkg/.env",
		"/etc/shadow",
	}
}

// Capabilities deduplicates witness capabilities, highest weight first.
func Capabilities(ws []Witness) []string {
	found := map[string]bool{}
	var caps []string
	for _, w := range ws {
		if !found[w.Capability] {
			found[w.Capability] = true
			caps = append(caps, w.Capability)
		}
	}
	// stable by weight
	for i := 0; i < len(caps); i++ {
		for j := i + 1; j < len(caps); j++ {
			if Weights[caps[j]] > Weights[caps[i]] {
				caps[i], caps[j] = caps[j], caps[i]
			}
		}
	}
	return caps
}

// MaxWeight is the highest capability weight among witnesses.
func MaxWeight(ws []Witness) float64 {
	return Weight(Capabilities(ws))
}
