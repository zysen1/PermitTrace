package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallPreservesPermissionsAndDoesNotDuplicate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte("{\n  \"permissions\": {\"allow\": [\"Bash(go test)\"]}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := installHooks(path, "/usr/local/bin/permittrace"); err != nil {
		t.Fatal(err)
	}
	if err := installHooks(path, "/usr/local/bin/permittrace"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if strings.Count(text, "permittrace hook") != 2 {
		t.Fatalf("hook count\n%s", text)
	}
	if !strings.Contains(text, "Bash(go test)") {
		t.Fatalf("permissions dropped\n%s", text)
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Fatal("missing backup", err)
	}
}
