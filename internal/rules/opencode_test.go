package rules

import "testing"

func TestOpenCodeLastMatchWins(t *testing.T) {
	raw := []byte(`{
	  "$schema": "https://opencode.ai/config.json",
	  "permission": {
	    "bash": {
	      "*": "ask",
	      "git *": "allow",
	      "git commit *": "deny",
	      "git push *": "deny",
	      "grep *": "allow"
	    },
	    "edit": "deny",
	    "webfetch": {
	      "*": "ask",
	      "https://en.wikipedia.org/*": "allow"
	    }
	  }
	}`)
	rules, err := ParseOpenCode(raw)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		perm, in, want string
	}{
		{"bash", "git status", "allow"},
		{"bash", "git commit -am x", "deny"},
		{"bash", "git push origin main", "deny"},
		{"bash", "grep pattern file.txt", "allow"},
		{"bash", "rm -rf /", "ask"},
		{"edit", "src/main.go", "deny"},
		{"webfetch", "https://en.wikipedia.org/wiki/X", "allow"},
		{"webfetch", "https://evil.example/x", "ask"},
	}
	for _, tc := range cases {
		got := DecideOpenCode(rules, tc.perm, tc.in)
		if got != tc.want {
			t.Errorf("%s %q = %q want %q", tc.perm, tc.in, got, tc.want)
		}
	}
}

func TestOpenCodeQuestionMark(t *testing.T) {
	if !openCodeMatch("git ?", "git s") {
		t.Fatal("? should match one character")
	}
	if openCodeMatch("git ?", "git status") {
		t.Fatal("? should not match many characters")
	}
}

func TestOpenCodeGlobalString(t *testing.T) {
	rules, err := ParseOpenCode([]byte(`{"permission":"allow"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := DecideOpenCode(rules, "bash", "rm -rf /"); got != "allow" {
		t.Fatalf("got %q", got)
	}
}
