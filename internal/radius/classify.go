package radius

import (
	"strings"

	"github.com/zysen1/PermitTrace/internal/shell"
)

// Weights are the capability weights used by the risk score.
// arbitrary execution outranks a plain network call so that `curl | sh`
// denies and a single fetch can still be narrowed or asked about.
var Weights = map[string]float64{
	"arbitrary_exec":       1.00,
	"privilege_escalation": 0.95,
	"read_secrets":         0.85,
	"persistence":          0.80,
	"write_outside":        0.75,
	"network_exfil":        0.70,
}

// Weight returns the highest weight among caps.
func Weight(caps []string) float64 {
	max := 0.0
	for _, c := range caps {
		if w := Weights[c]; w > max {
			max = w
		}
	}
	return max
}

// Classify assigns capabilities to a shell command from its syntax and arguments.
func Classify(command string) []string {
	a := shell.Parse(command)
	found := map[string]bool{}
	add := func(c string) {
		if c != "" {
			found[c] = true
		}
	}
	text := strings.ToLower(command)
	if !a.OK {
		// Still look at the raw text. An unparseable string is not a free pass.
		classifyText(text, add)
	}
	for _, f := range a.Findings {
		switch f.Kind {
		case "pipe_to_shell":
			add("arbitrary_exec")
			if strings.Contains(strings.ToLower(f.Text), "curl") || strings.Contains(strings.ToLower(f.Text), "wget") {
				add("network_exfil")
			}
		case "eval", "shell_c":
			add("arbitrary_exec")
			if strings.Contains(text, "curl") || strings.Contains(text, "wget") || strings.Contains(text, "http") {
				add("network_exfil")
			}
		}
	}
	cmds := a.Subcommands
	if len(a.Calls) > 0 {
		cmds = a.Calls
	}
	for _, c := range cmds {
		argv := c.Argv
		if len(argv) == 0 {
			argv = strings.Fields(c.Normalized)
		}
		classifyArgv(argv, strings.ToLower(c.Text+" "+c.Normalized), add)
	}
	if len(cmds) == 0 {
		classifyArgv(strings.Fields(command), text, add)
	}
	classifyText(text, add)
	return keys(found)
}

func classifyArgv(argv []string, lower string, add func(string)) {
	if len(argv) == 0 {
		return
	}
	prog := base(argv[0])
	rest := argv[1:]
	switch prog {
	case "curl", "wget":
		add("network_exfil")
		if containsSecret(lower) {
			add("read_secrets")
		}
	case "nc", "ncat", "socat", "scp", "rsync":
		add("network_exfil")
		if containsSecret(lower) {
			add("read_secrets")
		}
	case "ssh":
		if len(rest) > 0 {
			add("network_exfil")
		}
	case "python", "python3", "node", "perl", "ruby", "php":
		if hasExecFlag(rest) {
			add("arbitrary_exec")
		}
	case "sudo", "pkexec", "doas":
		add("privilege_escalation")
	case "chmod":
		if strings.Contains(lower, "+s") || strings.Contains(lower, "4755") || strings.Contains(lower, "u+s") {
			add("privilege_escalation")
		}
	case "chown", "usermod":
		if prog == "usermod" || strings.Contains(lower, "root") {
			add("privilege_escalation")
		}
	case "rm":
		if recursiveRemove(rest) {
			add("write_outside")
			joined := strings.Join(rest, " ")
			if strings.Contains(joined, "/") && !strings.Contains(joined, "./") {
				add("arbitrary_exec")
			}
		}
	case "dd":
		if strings.Contains(lower, "of=/dev") {
			add("write_outside")
		}
	case "cat", "head", "tail", "less", "more", "base64":
		if containsSecret(lower) {
			add("read_secrets")
		}
	case "printenv":
		add("read_secrets")
	case "env":
		if len(rest) == 0 {
			add("read_secrets")
		}
	case "crontab":
		add("persistence")
	case "npx", "uvx":
		if containsAny(rest, "--yes", "-y") || containsLocalPath(rest) {
			add("arbitrary_exec")
			add("network_exfil")
		}
	case "npm", "pnpm", "yarn":
		if len(rest) >= 2 && rest[0] == "install" && containsAny(rest, "-g", "--global") {
			add("persistence")
			add("network_exfil")
		}
	case "docker":
		if containsAny(rest, "--privileged") {
			add("privilege_escalation")
			add("arbitrary_exec")
		}
	case "tee", "install", "mv", "cp", "shred":
		if writesOutside(lower) {
			add("write_outside")
		}
		if containsSecret(lower) {
			add("read_secrets")
		}
		if persistentTarget(lower) {
			add("persistence")
		}
	case "git":
		if gitSub(rest) == "config" {
			add("persistence")
		}
		if gitSub(rest) == "push" && containsAny(rest, "--mirror") {
			add("network_exfil")
			add("persistence")
		}
	case "echo":
		if persistentTarget(lower) {
			add("persistence")
		}
	}
	if persistentTarget(lower) && (prog == "tee" || strings.Contains(lower, ">>")) {
		add("persistence")
	}
}

func classifyText(lower string, add func(string)) {
	if persistentTarget(lower) && (strings.Contains(lower, ">>") || strings.Contains(lower, "tee ")) {
		add("persistence")
	}
	if strings.Contains(lower, "/etc/sudoers") || strings.Contains(lower, "authorized_keys") {
		add("persistence")
		add("privilege_escalation")
	}
}

func hasExecFlag(args []string) bool {
	for _, a := range args {
		if a == "-e" || a == "-c" || a == "-r" || strings.HasPrefix(a, "--eval") {
			return true
		}
	}
	return false
}

func recursiveRemove(args []string) bool {
	flags := ""
	for _, a := range args {
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") {
			flags += a
		}
		if a == "--recursive" || a == "--force" {
			flags += "rf"
		}
	}
	return strings.Contains(flags, "r") && strings.Contains(flags, "f")
}

func containsSecret(lower string) bool {
	needles := []string{
		".ssh", "id_rsa", "id_ed25519", ".aws", "credentials", ".env",
		"/etc/shadow", ".npmrc", ".kube", "secring", "hosts.yml", ".gnupg",
		".pypirc", ".netrc", "secrets",
	}
	for _, n := range needles {
		if strings.Contains(lower, n) {
			return true
		}
	}
	return false
}

func persistentTarget(lower string) bool {
	needles := []string{
		".bashrc", ".zshrc", ".profile", ".bash_profile", "authorized_keys",
		"crontab", ".git/hooks", "systemd", "/etc/cron", "sudoers",
	}
	for _, n := range needles {
		if strings.Contains(lower, n) {
			return true
		}
	}
	return false
}

func writesOutside(lower string) bool {
	needles := []string{"/etc/", "/usr/", "/bin/", "/dev/", "/tmp/", "/home/", " /"}
	for _, n := range needles {
		if strings.Contains(lower, n) {
			return true
		}
	}
	return false
}

func containsLocalPath(args []string) bool {
	for _, a := range args {
		if a == "." || strings.HasPrefix(a, "./") || strings.HasPrefix(a, "/") || strings.HasPrefix(a, "../") {
			return true
		}
	}
	return false
}

func containsAny(args []string, want ...string) bool {
	for _, a := range args {
		for _, w := range want {
			if a == w {
				return true
			}
		}
	}
	return false
}

func gitSub(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			if a == "-C" || a == "-c" || a == "--git-dir" || a == "--work-tree" {
				i++
			}
			continue
		}
		return a
	}
	return ""
}

func base(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		p = p[i+1:]
	}
	return strings.TrimSuffix(p, ".exe")
}

func keys(m map[string]bool) []string {
	order := []string{"arbitrary_exec", "privilege_escalation", "read_secrets", "persistence", "write_outside", "network_exfil"}
	var out []string
	for _, k := range order {
		if m[k] {
			out = append(out, k)
		}
	}
	return out
}
