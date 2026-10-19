package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/zysen1/PermitTrace/internal/audit"
	"github.com/zysen1/PermitTrace/internal/bench"
	"github.com/zysen1/PermitTrace/internal/engine"
	"github.com/zysen1/PermitTrace/internal/hook"
	"github.com/zysen1/PermitTrace/internal/indirect"
	"github.com/zysen1/PermitTrace/internal/report"
	"github.com/zysen1/PermitTrace/internal/rules"
	"github.com/zysen1/PermitTrace/internal/trace"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "hook":
		if err := hook.Run(os.Stdin, os.Stdout, nil); err != nil {
			fmt.Fprintln(os.Stderr, "permittrace hook:", err)
			os.Exit(1)
		}
	case "audit":
		dir := "."
		if len(os.Args) > 2 {
			dir = os.Args[2]
		}
		findings, err := audit.Scan(dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if len(findings) == 0 {
			fmt.Println("No dangerous allow rules found.")
			return
		}
		for _, f := range findings {
			fmt.Printf("%s  %s  %s\n", f.Harness, f.File, f.Rule)
			fmt.Printf("  capabilities: %s\n", strings.Join(f.Capabilities, ", "))
			for _, ex := range f.Examples {
				fmt.Printf("  would also allow: %s\n", ex)
			}
		}
		os.Exit(1)
	case "replay":
		if err := cmdReplay(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "bench":
		if err := cmdBench(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "generate":
		out := "fixtures"
		if len(os.Args) > 2 {
			out = os.Args[2]
		}
		if err := bench.Materialize(out, bench.Catalog()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("wrote", out)
	case "demo":
		if err := cmdDemo(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "report":
		if err := cmdReport(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "install":
		if err := cmdInstall(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "version", "--version", "-v":
		fmt.Println("permittrace", version)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `permittrace %s — every permission has a provenance

  permittrace hook                         Claude Code PreToolUse / PermissionRequest hook
  permittrace audit [dir]                  scan .claude/settings*.json and opencode.json
  permittrace replay <trace.jsonl> [--repo dir] [--out report.html]
  permittrace bench                        run AllowRuleBench-mini (this repo's dataset)
  permittrace generate [fixtures]          write the bench scenarios to disk
  permittrace demo [--out report.html]     the "README that wants root" replay
  permittrace report --in result.json [--out report.html] [--open]
  permittrace install [--settings file]    merge hook config, after backing up the file
  permittrace version
`, version)
}

func cmdReplay(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: permittrace replay <trace.jsonl> [--repo dir] [--out report.html]")
	}
	path := args[0]
	repo := ""
	out := "permittrace-report.html"
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--repo":
			i++
			repo = args[i]
		case "--out":
			i++
			out = args[i]
		default:
			return fmt.Errorf("unknown flag %s", args[i])
		}
	}
	recs, err := trace.Load(path)
	if err != nil {
		return err
	}
	in, err := inputFromSegments(recs, repo)
	if err != nil {
		return err
	}
	if req, err := lastHook(path); err == nil && req.ToolName != "" {
		if req.ToolName != "" {
			in.Tool = req.ToolName
		}
		if c := strField(req.ToolInput, "command"); c != "" {
			in.Command = c
		}
		if p := strField(req.ToolInput, "file_path"); p != "" {
			in.FilePath = p
		}
		if u := strField(req.ToolInput, "url"); u != "" {
			in.URL = u
		}
		for _, s := range req.PermissionSuggestions {
			u := engine.Update{Type: s.Type, Behavior: s.Behavior, Destination: s.Destination, Mode: s.Mode}
			for _, r := range s.Rules {
				spec := r.RuleContent
				tool := r.ToolName
				raw := tool
				if spec != "" {
					raw = tool + "(" + spec + ")"
				}
				u.Rules = append(u.Rules, rules.ParseRule(raw))
			}
			in.Suggestions = append(in.Suggestions, u)
		}
	}
	if repo != "" {
		idx, err := indirect.Load(repo)
		if err != nil {
			return err
		}
		in.Repo = idx
	}
	res := engine.Decide(in)
	fmt.Print(report.Card(res))
	return writeReport(out, filepath.Base(path), res)
}

func lastHook(path string) (hook.Request, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return hook.Request{}, err
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) == 0 {
		return hook.Request{}, fmt.Errorf("empty")
	}
	var req hook.Request
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &req); err != nil {
		return hook.Request{}, err
	}
	return req, nil
}

func strField(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	s, _ := m[k].(string)
	return s
}

func inputFromSegments(segs []engine.Segment, repo string) (engine.Input, error) {
	if len(segs) == 0 {
		return engine.Input{}, fmt.Errorf("empty trace")
	}
	// The request is the last segment that names a tool command, path, or URL-like text.
	req := segs[len(segs)-1]
	in := engine.Input{Segments: segs, Tool: "Bash", Cwd: repo, Command: req.Command, FilePath: req.FilePath}
	if req.Tool != "" && req.Tool != "context" && req.Tool != "user" {
		in.Tool = req.Tool
	}
	if in.Command == "" && in.FilePath == "" {
		in.Command = strings.TrimSpace(req.Text)
	}
	return in, nil
}

func cmdDemo(args []string) error {
	out := "permittrace-report.html"
	for i := 0; i < len(args); i++ {
		if args[i] == "--out" && i+1 < len(args) {
			i++
			out = args[i]
		}
	}
	var sc bench.Scenario
	found := false
	for _, s := range bench.Catalog() {
		if s.ID == "contributing-line42" {
			sc = s
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("demo scenario missing")
	}
	dir, err := os.MkdirTemp("", "permittrace-demo-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := bench.Materialize(dir, []bench.Scenario{sc}); err != nil {
		return err
	}
	repo := filepath.Join(dir, sc.Split, sc.ID, "repo")
	idx, err := indirect.Load(repo)
	if err != nil {
		return err
	}
	hookPath := filepath.Join(dir, sc.Split, sc.ID, "hook.json")
	body, err := os.ReadFile(hookPath)
	if err != nil {
		return err
	}
	var buf strings.Builder
	if err := hook.Run(strings.NewReader(string(body)), &buf, func(in engine.Input) engine.Result {
		in.Repo = idx
		recs, err := trace.Load(filepath.Join(dir, sc.Split, sc.ID, "transcript.jsonl"))
		if err == nil {
			in.Segments = recs
		}
		return engine.Decide(in)
	}); err != nil {
		return err
	}
	// Re-decide for the report so we keep the structured result, not only JSON.
	recs, err := trace.Load(filepath.Join(dir, sc.Split, sc.ID, "transcript.jsonl"))
	if err != nil {
		return err
	}
	in := engine.Input{Tool: "Bash", Command: sc.Command, Repo: idx, Segments: recs, Cwd: repo}
	in.Suggestions = []engine.Update{{
		Type: "addRules", Behavior: "allow", Destination: "localSettings",
		Rules: []rules.Rule{rules.ParseRule("Bash(" + sc.RuleSpec + ")")},
	}}
	res := engine.Decide(in)
	fmt.Print(report.Card(res))
	fmt.Println()
	fmt.Println("hook stdout:")
	fmt.Print(buf.String())
	if err := writeReport(out, "README that wants root", res); err != nil {
		return err
	}
	fmt.Println("report:", out)
	return nil
}

func cmdBench(args []string) error {
	cold := true
	for _, a := range args {
		if a == "--no-cold" {
			cold = false
		}
	}
	sum := bench.Evaluate(bench.Catalog())
	fmt.Print(sum.Markdown())
	if cold {
		p50, p95, n, err := coldStart()
		if err != nil {
			fmt.Fprintf(os.Stderr, "cold start not measured: %v\n", err)
			return nil
		}
		fmt.Printf("\n### Process cold start\n\n`permittrace hook` on a one-line PreToolUse event, %d new processes on this machine (%s/%s).\n\n| Metric | Value |\n|---|---|\n| p50 | %.2f ms |\n| p95 | %.2f ms |\n", n, runtime.GOOS, runtime.GOARCH, p50, p95)
	}
	return nil
}

func coldStart() (p50, p95 float64, n int, err error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, 0, 0, err
	}
	payload := []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/tmp","tool_input":{"command":"go test ./..."}}`)
	var samples []float64
	n = 21
	for i := 0; i < n; i++ {
		cmd := exec.Command(exe, "hook")
		cmd.Stdin = strings.NewReader(string(payload))
		t0 := time.Now()
		out, err := cmd.Output()
		elapsed := time.Since(t0)
		if err != nil {
			return 0, 0, 0, err
		}
		if !json.Valid(out) {
			return 0, 0, 0, fmt.Errorf("hook stdout was not JSON: %s", out)
		}
		samples = append(samples, float64(elapsed.Microseconds())/1000)
	}
	sort.Float64s(samples)
	return samples[len(samples)/2], samples[int(float64(len(samples)-1)*0.95)], n, nil
}

func cmdReport(args []string) error {
	in := ""
	out := "permittrace-report.html"
	open := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--in":
			i++
			in = args[i]
		case "--out":
			i++
			out = args[i]
		case "--open":
			open = true
		default:
			return fmt.Errorf("unknown flag %s", args[i])
		}
	}
	if in == "" {
		return fmt.Errorf("usage: permittrace report --in result.json [--out report.html] [--open]")
	}
	body, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	var res engine.Result
	if err := json.Unmarshal(body, &res); err != nil {
		return err
	}
	if err := writeReport(out, "PermitTrace", res); err != nil {
		return err
	}
	fmt.Println(out)
	if open {
		return openFile(out)
	}
	return nil
}

func writeReport(path, title string, res engine.Result) error {
	b, err := report.HTML(title, res)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func openFile(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", abs)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", abs)
	default:
		cmd = exec.Command("xdg-open", abs)
	}
	return cmd.Start()
}

func cmdInstall(args []string) error {
	settings := filepath.Join(".claude", "settings.json")
	for i := 0; i < len(args); i++ {
		if args[i] == "--settings" && i+1 < len(args) {
			i++
			settings = args[i]
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}
	return installHooks(settings, exe)
}

func installHooks(settings, exe string) error {
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		return err
	}
	existing := map[string]any{}
	if b, err := os.ReadFile(settings); err == nil && len(strings.TrimSpace(string(b))) > 0 {
		if err := json.Unmarshal(b, &existing); err != nil {
			return fmt.Errorf("parse %s: %w", settings, err)
		}
		bak := settings + ".bak"
		if err := os.WriteFile(bak, b, 0o644); err != nil {
			return err
		}
		fmt.Println("backed up", settings, "to", bak)
	}
	hooks, _ := existing["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	cmd := exe + " hook"
	matcher := "Bash|Read|Edit|Write|WebFetch|PowerShell"
	for _, event := range []string{"PreToolUse", "PermissionRequest"} {
		hooks[event] = mergeHook(hooks[event], matcher, cmd)
	}
	existing["hooks"] = hooks
	out, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	if err := os.WriteFile(settings, out, 0o644); err != nil {
		return err
	}
	fmt.Println("installed", cmd, "into", settings)
	return nil
}

func mergeHook(current any, matcher, command string) any {
	var groups []any
	if arr, ok := current.([]any); ok {
		groups = arr
	}
	for _, g := range groups {
		gm, ok := g.(map[string]any)
		if !ok {
			continue
		}
		hs, _ := gm["hooks"].([]any)
		for _, h := range hs {
			hm, ok := h.(map[string]any)
			if !ok {
				continue
			}
			if c, _ := hm["command"].(string); strings.Contains(c, "permittrace hook") {
				hm["command"] = command
				gm["matcher"] = matcher
				return groups
			}
		}
	}
	groups = append(groups, map[string]any{
		"matcher": matcher,
		"hooks": []any{map[string]any{
			"type":    "command",
			"command": command,
		}},
	})
	return groups
}
