// Package indirect resolves repository-controlled commands that a shell rule
// would launch without showing the real program in the rule text: package.json
// scripts, Makefile targets, justfile recipes, git aliases, and pre-commit hooks.
package indirect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/zysen1/PermitTrace/internal/shell"
	"gopkg.in/yaml.v3"
)

// Leaf is one concrete shell string reached by expanding a command.
type Leaf struct {
	Command string
	Source  string // repo-relative file, or "command"
	Via     string // the command that pointed here
}

// Index is the indirect-execution surface of one repository.
type Index struct {
	Root      string
	Scripts   map[string]Script
	Targets   map[string]Recipe
	Recipes   map[string]Recipe
	Aliases   map[string]Alias
	Hooks     []Hook
	FirstMake string
}

// Script is one package.json script.
type Script struct {
	Name   string
	Body   string
	Source string
}

// Recipe is a Makefile target or a justfile recipe.
type Recipe struct {
	Name   string
	Body   string
	Source string
}

// Alias is a git alias. Shell is true when the value starts with "!".
type Alias struct {
	Name   string
	Value  string
	Shell  bool
	Source string
}

// Hook is one pre-commit hook entry.
type Hook struct {
	ID     string
	Entry  string
	Source string
}

// Load reads the supported files under root. Missing files are not errors.
func Load(root string) (*Index, error) {
	if root == "" {
		root = "."
	}
	idx := &Index{
		Root:    root,
		Scripts: map[string]Script{},
		Targets: map[string]Recipe{},
		Recipes: map[string]Recipe{},
		Aliases: map[string]Alias{},
	}
	idx.loadPackageJSON(filepath.Join(root, "package.json"))
	idx.loadMakefile(filepath.Join(root, "Makefile"))
	if _, err := os.Stat(filepath.Join(root, "makefile")); err == nil && len(idx.Targets) == 0 {
		idx.loadMakefile(filepath.Join(root, "makefile"))
	}
	idx.loadJust(filepath.Join(root, "justfile"))
	if len(idx.Recipes) == 0 {
		idx.loadJust(filepath.Join(root, "Justfile"))
	}
	idx.loadGitConfig(filepath.Join(root, ".git", "config"))
	// permittrace.gitconfig is a portable [alias] section so fixtures can be
	// cloned without a nested .git directory. Same-named aliases in this file
	// override .git/config.
	idx.loadGitConfig(filepath.Join(root, "permittrace.gitconfig"))
	idx.loadPreCommit(filepath.Join(root, ".pre-commit-config.yaml"))
	return idx, nil
}

func (idx *Index) loadPackageJSON(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var doc struct {
		Scripts map[string]any `json:"scripts"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return
	}
	rel := rel(idx.Root, path)
	for name, v := range doc.Scripts {
		body, ok := v.(string)
		if !ok {
			continue
		}
		idx.Scripts[name] = Script{Name: name, Body: body, Source: rel}
	}
}

func (idx *Index) loadMakefile(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	rel := rel(idx.Root, path)
	lines := strings.Split(string(b), "\n")
	var name string
	var body []string
	flush := func() {
		if name == "" {
			return
		}
		idx.Targets[name] = Recipe{Name: name, Body: strings.Join(body, "\n"), Source: rel}
		if idx.FirstMake == "" && !strings.HasPrefix(name, ".") {
			idx.FirstMake = name
		}
		name = ""
		body = nil
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "        ") {
			if name != "" {
				body = append(body, strings.TrimLeft(line, " \t"))
			}
			continue
		}
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			if trim == "" {
				flush()
			}
			continue
		}
		if strings.HasPrefix(trim, ".") && !strings.Contains(trim, ":") {
			continue
		}
		if i := strings.IndexByte(trim, ':'); i > 0 && !strings.HasPrefix(trim, "\t") {
			flush()
			left := strings.TrimSpace(trim[:i])
			// skip variable assignments like FOO := bar that contain no colon rule
			if strings.Contains(left, "=") || strings.HasPrefix(left, ".") {
				name = ""
				continue
			}
			// first target name only
			fields := strings.Fields(left)
			if len(fields) == 0 {
				continue
			}
			name = fields[0]
			body = nil
			continue
		}
		flush()
	}
	flush()
}

func (idx *Index) loadJust(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	rel := rel(idx.Root, path)
	lines := strings.Split(string(b), "\n")
	var name string
	var body []string
	flush := func() {
		if name == "" {
			return
		}
		idx.Recipes[name] = Recipe{Name: name, Body: strings.Join(body, "\n"), Source: rel}
		name = ""
		body = nil
	}
	for _, line := range lines {
		if name != "" && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) {
			body = append(body, strings.TrimSpace(line))
			continue
		}
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, "set ") || strings.HasPrefix(trim, "[") {
			if trim == "" {
				flush()
			}
			continue
		}
		if strings.HasSuffix(trim, ":") && !strings.Contains(trim, " ") {
			flush()
			name = strings.TrimSuffix(trim, ":")
			continue
		}
		// "name arg:" form — recipe name is the first field, drop the colon
		if strings.Contains(trim, ":") && !strings.HasPrefix(trim, "@") {
			head := strings.TrimSpace(strings.Split(trim, ":")[0])
			fields := strings.Fields(head)
			if len(fields) >= 1 && !strings.Contains(fields[0], "=") {
				flush()
				name = fields[0]
				continue
			}
		}
		flush()
	}
	flush()
}

func (idx *Index) loadGitConfig(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	rel := rel(idx.Root, path)
	section := ""
	for _, line := range strings.Split(string(b), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, ";") {
			continue
		}
		if strings.HasPrefix(trim, "[") && strings.HasSuffix(trim, "]") {
			section = strings.ToLower(strings.Trim(trim, "[]"))
			section = strings.Fields(section)[0]
			continue
		}
		if section != "alias" {
			continue
		}
		k, v, ok := strings.Cut(trim, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"`)
		a := Alias{Name: k, Value: v, Source: rel}
		if strings.HasPrefix(v, "!") {
			a.Shell = true
			a.Value = strings.TrimPrefix(v, "!")
		}
		idx.Aliases[k] = a
	}
}

type preCommitFile struct {
	Repos []struct {
		Hooks []struct {
			ID       string   `yaml:"id"`
			Entry    string   `yaml:"entry"`
			Args     []string `yaml:"args"`
			Language string   `yaml:"language"`
		} `yaml:"hooks"`
	} `yaml:"repos"`
}

func (idx *Index) loadPreCommit(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var doc preCommitFile
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return
	}
	rel := rel(idx.Root, path)
	for _, repo := range doc.Repos {
		for _, h := range repo.Hooks {
			entry := strings.TrimSpace(h.Entry)
			if entry == "" {
				continue
			}
			if len(h.Args) > 0 {
				entry = entry + " " + strings.Join(h.Args, " ")
			}
			idx.Hooks = append(idx.Hooks, Hook{ID: h.ID, Entry: entry, Source: rel})
		}
	}
}

// Expand returns the command itself and every repo-controlled body it reaches.
func (idx *Index) Expand(command string) []Leaf {
	seen := map[string]bool{}
	var out []Leaf
	idx.expand(command, "", 0, seen, &out)
	return out
}

func (idx *Index) expand(command, via string, depth int, seen map[string]bool, out *[]Leaf) {
	command = strings.TrimSpace(command)
	if command == "" || depth > 6 || seen[command] {
		return
	}
	seen[command] = true
	*out = append(*out, Leaf{Command: command, Via: via, Source: "command"})
	if idx == nil {
		return
	}
	if name, ok := scriptName(command); ok {
		if sc, ok := idx.Scripts[name]; ok {
			idx.expandBody(sc.Body, sc.Source, command, depth, seen, out)
		}
	}
	if name, ok := makeTarget(command); ok {
		if name == "" {
			name = idx.FirstMake
		}
		if rc, ok := idx.Targets[name]; ok {
			idx.expandBody(rc.Body, rc.Source, command, depth, seen, out)
		}
	}
	if name, ok := justRecipe(command); ok {
		if rc, ok := idx.Recipes[name]; ok {
			idx.expandBody(rc.Body, rc.Source, command, depth, seen, out)
		}
	}
	if name, ok := gitAliasName(command); ok {
		if al, ok := idx.Aliases[name]; ok {
			body := al.Value
			if !al.Shell {
				body = "git " + al.Value
			}
			idx.expandBody(body, al.Source, command, depth, seen, out)
		}
	}
	if runsHooks(command) {
		for _, h := range idx.Hooks {
			idx.expandBody(h.Entry, h.Source, command, depth, seen, out)
		}
	}
}

func (idx *Index) expandBody(body, source, via string, depth int, seen map[string]bool, out *[]Leaf) {
	body = strings.TrimSpace(body)
	if body == "" || seen["body:"+body] {
		return
	}
	seen["body:"+body] = true
	*out = append(*out, Leaf{Command: body, Via: via, Source: source})
	a := shell.Parse(body)
	cmds := a.Subcommands
	if !a.OK {
		return
	}
	for _, s := range cmds {
		text := s.Normalized
		if text == "" {
			text = s.Text
		}
		idx.expand(text, source, depth+1, seen, out)
	}
	// Nested calls such as bash -c '...' are expanded as their own text too.
	for _, c := range a.Calls {
		if strings.TrimSpace(c.Text) == "" || strings.TrimSpace(c.Text) == body {
			continue
		}
		idx.expand(c.Text, source, depth+1, seen, out)
	}
}

func scriptName(command string) (string, bool) {
	argv := argvOf(command)
	if len(argv) == 0 {
		return "", false
	}
	prog := base(argv[0])
	switch prog {
	case "npm", "pnpm", "yarn", "bun":
	default:
		return "", false
	}
	args := argv[1:]
	if len(args) == 0 {
		return "", false
	}
	if args[0] == "run" {
		if len(args) < 2 {
			return "", false
		}
		return args[1], true
	}
	switch args[0] {
	case "test", "start", "stop", "restart":
		return args[0], true
	default:
		return "", false
	}
}

func makeTarget(command string) (string, bool) {
	argv := argvOf(command)
	if len(argv) == 0 || base(argv[0]) != "make" {
		return "", false
	}
	for _, a := range argv[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a, true
	}
	return "", true // bare make, caller uses the first target
}

func justRecipe(command string) (string, bool) {
	argv := argvOf(command)
	if len(argv) == 0 || base(argv[0]) != "just" {
		return "", false
	}
	for _, a := range argv[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a, true
	}
	return "", false
}

func gitAliasName(command string) (string, bool) {
	argv := argvOf(command)
	if len(argv) == 0 || base(argv[0]) != "git" {
		return "", false
	}
	sub := gitSubcommand(argv[1:])
	if sub == "" {
		return "", false
	}
	switch sub {
	case "commit", "status", "diff", "log", "push", "pull", "fetch", "clone", "config", "add", "reset", "checkout", "switch", "merge", "rebase", "init", "show", "rev-parse", "describe", "stash", "tag", "branch", "remote":
		return "", false
	default:
		return sub, true
	}
}

func runsHooks(command string) bool {
	argv := argvOf(command)
	if len(argv) == 0 {
		return false
	}
	if base(argv[0]) == "pre-commit" {
		return true
	}
	if base(argv[0]) == "git" && gitSubcommand(argv[1:]) == "commit" {
		return true
	}
	return false
}

func gitSubcommand(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if strings.HasPrefix(a, "-") {
			// -C and -c take a value
			if a == "-C" || a == "-c" || a == "--git-dir" || a == "--work-tree" {
				i++
			}
			continue
		}
		return a
	}
	return ""
}

func argvOf(command string) []string {
	a := shell.Parse(command)
	if a.OK && len(a.Subcommands) > 0 && len(a.Subcommands[0].Argv) > 0 {
		return a.Subcommands[0].Argv
	}
	return strings.Fields(command)
}

func base(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func rel(root, path string) string {
	r, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(r)
}
