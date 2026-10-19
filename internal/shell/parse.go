// Package shell parses bash the way Claude Code's permission matcher describes
// it: compound commands are split, a fixed wrapper list is stripped, and
// structures that hide a second command are reported.
//
// The wrapper list and the separator set are taken from the Claude Code
// permissions reference (fetched 2026-10-19):
// https://code.claude.com/docs/en/permissions
// Separators: && || ; | |& & and newlines.
// Wrappers: timeout, time, nice, nohup, stdbuf, command, builtin, noglob,
// and bare xargs (no flags). command -v / command -V are not stripped.
// The only environment assignment the reference names as known-safe is
// NODE_ENV. Allow-matching therefore strips only NODE_ENV. Deny and ask
// matching strip every leading assignment, because the reference says a
// deny rule still matches past any assignment.
package shell

import (
	"bytes"
	"strings"
	"sync"

	"mvdan.cc/sh/v3/syntax"
)

// parseCache keeps hook latency down when the same corpus command is parsed
// on every decision. Analyses are not mutated after return.
var parseCache sync.Map

// Finding is a structural pattern the permission text does not show on its own.
type Finding struct {
	Kind string // command_substitution, eval, shell_c, pipe_to_shell
	Text string
}

// Subcommand is one simple command after compound splitting.
type Subcommand struct {
	Text       string   // source text
	Normalized string   // allow-normalized (NODE_ENV and wrappers removed)
	DenyText   string   // deny-normalized (any leading assignment and wrappers removed)
	Argv       []string // argv of the normalized command
}

// Analysis is the parse of one bash command string.
type Analysis struct {
	Raw         string
	OK          bool
	Subcommands []Subcommand
	// Calls includes nested simple commands (command substitutions, subshells,
	// loop bodies). Deny and ask rules consult Calls; allow rules consult
	// Subcommands only, matching the reference.
	Calls    []Subcommand
	Findings []Finding
}

// Parse analyzes src. A non-nil error from the parser marks OK false; callers
// must not treat an unparseable command as matched by a prefix allow rule.
func Parse(src string) Analysis {
	src = strings.TrimSpace(src)
	if v, ok := parseCache.Load(src); ok {
		return v.(Analysis)
	}
	a := parseNew(src)
	parseCache.Store(src, a)
	return a
}

func parseNew(src string) Analysis {
	a := Analysis{Raw: src}
	if src == "" {
		return a
	}
	parser := syntax.NewParser(syntax.KeepComments(false))
	file, err := parser.Parse(strings.NewReader(src), "")
	if err != nil || file == nil {
		return a
	}
	a.OK = true
	var subs []*syntax.Stmt
	for _, st := range file.Stmts {
		subs = append(subs, splitStmt(st)...)
	}
	for _, st := range subs {
		text := slice(src, st)
		norm, argv := normalizeStmt(src, st, false)
		deny, _ := normalizeStmt(src, st, true)
		a.Subcommands = append(a.Subcommands, Subcommand{
			Text: text, Normalized: norm, DenyText: deny, Argv: argv,
		})
	}
	syntax.Walk(file, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.CallExpr:
			text := slice(src, x)
			norm, argv := normalizeCall(src, x, false)
			deny, _ := normalizeCall(src, x, true)
			a.Calls = append(a.Calls, Subcommand{
				Text: text, Normalized: norm, DenyText: deny, Argv: argv,
			})
			if len(argv) > 0 {
				switch argv[0] {
				case "eval":
					a.Findings = append(a.Findings, Finding{Kind: "eval", Text: text})
				case "sh", "bash", "zsh", "dash", "ash":
					if hasFlag(argv[1:], "c") {
						a.Findings = append(a.Findings, Finding{Kind: "shell_c", Text: text})
					}
				}
			}
		case *syntax.CmdSubst:
			a.Findings = append(a.Findings, Finding{Kind: "command_substitution", Text: slice(src, x)})
		case *syntax.BinaryCmd:
			if x.Op == syntax.Pipe || x.Op == syntax.PipeAll {
				if pipeToShell(x) {
					a.Findings = append(a.Findings, Finding{Kind: "pipe_to_shell", Text: slice(src, x)})
				}
			}
		}
		return true
	})
	return a
}

func splitStmt(st *syntax.Stmt) []*syntax.Stmt {
	if st == nil || st.Cmd == nil {
		return nil
	}
	switch c := st.Cmd.(type) {
	case *syntax.BinaryCmd:
		switch c.Op {
		case syntax.AndStmt, syntax.OrStmt, syntax.Pipe, syntax.PipeAll:
			return append(splitStmt(c.X), splitStmt(c.Y)...)
		}
	case *syntax.TimeClause:
		return splitStmt(c.Stmt)
	}
	return []*syntax.Stmt{st}
}

func pipeToShell(b *syntax.BinaryCmd) bool {
	argv := callArgv(b.Y)
	if len(argv) == 0 {
		return false
	}
	switch argv[0] {
	case "sh", "bash", "zsh", "dash", "ash", "source", ".":
		return true
	default:
		return false
	}
}

func callArgv(st *syntax.Stmt) []string {
	if st == nil {
		return nil
	}
	call, ok := st.Cmd.(*syntax.CallExpr)
	if !ok {
		return nil
	}
	var argv []string
	for _, w := range call.Args {
		argv = append(argv, wordText(w))
	}
	return argv
}

func normalizeStmt(src string, st *syntax.Stmt, stripAllEnv bool) (string, []string) {
	if st == nil || st.Cmd == nil {
		return "", nil
	}
	switch c := st.Cmd.(type) {
	case *syntax.TimeClause:
		return normalizeStmt(src, c.Stmt, stripAllEnv)
	case *syntax.CallExpr:
		return normalizeCall(src, c, stripAllEnv)
	default:
		return strings.TrimSpace(slice(src, st)), nil
	}
}

func normalizeCall(src string, call *syntax.CallExpr, stripAllEnv bool) (string, []string) {
	if call == nil {
		return "", nil
	}
	var assigns []string
	for _, as := range call.Assigns {
		assigns = append(assigns, slice(src, as))
	}
	startArg := 0
	args := call.Args
	for {
		if startArg >= len(args) {
			break
		}
		prog := wordText(args[startArg])
		switch prog {
		case "timeout":
			startArg += skipTimeout(args[startArg:])
		case "time":
			startArg += skipFlags(args[startArg:], map[string]bool{"-p": false})
		case "nice":
			startArg += skipFlags(args[startArg:], map[string]bool{"-n": true, "--adjustment": true})
		case "nohup":
			startArg++
		case "stdbuf":
			startArg += skipFlags(args[startArg:], map[string]bool{"-i": true, "-o": true, "-e": true, "--input": true, "--output": true, "--error": true})
		case "command":
			if isCommandQuery(args[startArg:]) {
				goto done
			}
			startArg += skipCommand(args[startArg:])
		case "builtin", "noglob":
			startArg++
		case "xargs":
			if xargsHasFlags(args[startArg+1:]) {
				goto done
			}
			startArg++
		default:
			goto done
		}
	}
done:
	var keepEnv []string
	if !stripAllEnv {
		keepEnv = filterEnv(assigns)
	}
	var argv []string
	for _, w := range args[startArg:] {
		argv = append(argv, wordText(w))
	}
	if len(argv) == 0 && len(keepEnv) == len(assigns) && len(assigns) > 0 && !stripAllEnv {
		// Nothing but assignments, or wrapper stripping consumed the command.
		return strings.TrimSpace(slice(src, call)), nil
	}
	var b strings.Builder
	for i, e := range keepEnv {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(e)
	}
	if len(keepEnv) > 0 && len(argv) > 0 {
		b.WriteByte(' ')
	}
	if startArg < len(args) {
		b.WriteString(strings.TrimSpace(slice(src, &syntax.CallExpr{Args: args[startArg:]})))
	} else if len(argv) > 0 {
		if b.Len() > 0 && !strings.HasSuffix(b.String(), " ") {
			b.WriteByte(' ')
		}
		b.WriteString(strings.Join(argv, " "))
	}
	return strings.TrimSpace(b.String()), argv
}

func filterEnv(assigns []string) []string {
	var out []string
	for _, a := range assigns {
		name, _, ok := strings.Cut(a, "=")
		if ok && name == "NODE_ENV" {
			continue
		}
		out = append(out, a)
	}
	return out
}

// skipTimeout returns how many words belong to the timeout wrapper, including
// the timeout token and its duration.
func skipTimeout(args []*syntax.Word) int {
	i := 1
	for i < len(args) {
		a := wordText(args[i])
		switch {
		case a == "--":
			i++
			if i < len(args) {
				i++ // duration
			}
			return i
		case a == "-k" || a == "--kill-after" || a == "-s" || a == "--signal":
			i++
			if i < len(args) {
				i++
			}
		case strings.HasPrefix(a, "-") && a != "-":
			i++
		default:
			i++ // duration
			return i
		}
	}
	return i
}

// flagsWithArg lists flags that consume the next word. A flag not in the map
// is treated as a boolean flag when it starts with "-".
func skipFlags(args []*syntax.Word, takesArg map[string]bool) int {
	i := 1
	for i < len(args) {
		a := wordText(args[i])
		if a == "--" {
			return i + 1
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			return i
		}
		if v, ok := takesArg[a]; ok && v {
			i += 2
			continue
		}
		i++
	}
	return i
}

func skipCommand(args []*syntax.Word) int {
	i := 1
	for i < len(args) {
		a := wordText(args[i])
		if a == "-p" || a == "--" {
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			i++
			continue
		}
		return i
	}
	return i
}

func isCommandQuery(args []*syntax.Word) bool {
	for _, w := range args[1:] {
		a := wordText(w)
		if a == "-v" || a == "-V" || a == "--" {
			return a == "-v" || a == "-V"
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return false
	}
	return false
}

func xargsHasFlags(args []*syntax.Word) bool {
	for _, w := range args {
		a := wordText(w)
		if strings.HasPrefix(a, "-") {
			return true
		}
	}
	return false
}

func hasFlag(argv []string, flag string) bool {
	for _, a := range argv {
		if a == "-"+flag || a == "--"+flag {
			return true
		}
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a, flag) && len(flag) == 1 {
			return true
		}
	}
	return false
}

func wordText(w *syntax.Word) string {
	if w == nil {
		return ""
	}
	var b bytes.Buffer
	_ = syntax.NewPrinter().Print(&b, w)
	return b.String()
}

func slice(src string, n syntax.Node) string {
	if n == nil {
		return ""
	}
	a := int(n.Pos().Offset())
	b := int(n.End().Offset())
	if a < 0 {
		a = 0
	}
	if b > len(src) {
		b = len(src)
	}
	if a > b {
		return ""
	}
	return src[a:b]
}
