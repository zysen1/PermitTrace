package rules

import "testing"

func TestBashWildcardTable(t *testing.T) {
	// Rows from the Claude Code permissions reference, "Wildcard patterns".
	cases := []struct {
		rule, cmd string
		want      bool
	}{
		{"Bash(npm run build)", "npm run build", true},
		{"Bash(npm run build)", "npm run build --watch", false},
		{"Bash(npm run *)", "npm run build", true},
		{"Bash(npm run *)", "npm run test --watch", true},
		{"Bash(npm run *)", "npm run", true},
		{"Bash(npm run *)", "npm install", false},
		{"Bash(git log * main)", "git log --oneline main", true},
		{"Bash(git log * main)", "git log -5 main", true},
		{"Bash(git log * main)", "git log --output= main", true},
		{"Bash(git log * main)", "git log main", false},
		{"Bash(git log * main)", "git push origin main", false},
		{"Bash(git * main)", "git merge main", true},
		{"Bash(git * main)", "git push origin main", true},
		{"Bash(git * main)", "git -c core.fsmonitor= diff main", true},
		{"Bash(git * main)", "git log", false},
		{"Bash(* --version)", "node --version", true},
		{"Bash(* --version)", "bash -c 'echo hi' --version", true},
		{"Bash(* --version)", "node -v", false},
		{"Bash(ls *)", "ls -la", true},
		{"Bash(ls *)", "ls", true},
		{"Bash(ls *)", "lsof", false},
		{"Bash(ls*)", "ls -la", true},
		{"Bash(ls*)", "lsof", true},
		{"Bash(* --help *)", "npm --help x", true},
		{"Bash(* --help *)", "npm --help", false},
		{"Bash(ls:*)", "ls", true},
		{"Bash(ls:*)", "ls -la", true},
		{"Bash(git:* push)", "git push", false},
	}
	for _, tc := range cases {
		r := ParseRule(tc.rule)
		r.Behavior = "allow"
		got := r.AllowsBash(tc.cmd)
		if got != tc.want {
			t.Errorf("allow %s vs %q = %v want %v", tc.rule, tc.cmd, got, tc.want)
		}
	}
}

func TestCompoundAllow(t *testing.T) {
	r := ParseRule("Bash(safe-cmd *)")
	r.Behavior = "allow"
	if r.AllowsBash("safe-cmd && other-cmd") {
		t.Fatal("compound must not be approved by one subcommand's rule")
	}
	if r.AllowsBash("npm test &&") {
		t.Fatal("unparseable trailing && must not match a prefix")
	}
	both := ParseRule("Bash(echo *)")
	if !both.AllowsBash("echo a && echo b") {
		t.Fatal("each subcommand matches echo *")
	}
}

func TestWrappersAllow(t *testing.T) {
	r := ParseRule("Bash(npm test *)")
	if !r.AllowsBash("timeout 30 npm test") {
		t.Fatal("timeout wrapper")
	}
	if !r.AllowsBash("NODE_ENV=test npm test") {
		t.Fatal("NODE_ENV")
	}
	if r.AllowsBash("FOO=bar npm test") {
		t.Fatal("unknown assignment must block allow match")
	}
	if !r.AllowsBash("xargs npm test") {
		// xargs npm test normalizes to "npm test", and "npm test *" matches bare "npm test"
		t.Fatal("bare xargs")
	}
}

func TestDenyNested(t *testing.T) {
	r := ParseRule("Bash(git clean *)")
	r.Behavior = "deny"
	if !r.MatchesBashDeny("cd /tmp && git clean -f") {
		t.Fatal("deny matches a subcommand")
	}
	if !r.MatchesBashDeny(`echo "$(git clean -f)"`) {
		t.Fatal("deny matches inside command substitution")
	}
	if !r.MatchesBashDeny("FOO=bar git clean -f") {
		t.Fatal("deny matches past any assignment")
	}
	allow := ParseRule("Bash(echo *)")
	allow.Behavior = "allow"
	if !allow.AllowsBash(`echo "$(git clean -f)"`) {
		t.Fatal("allow sees the outer command")
	}
}

func TestWebFetchDomains(t *testing.T) {
	cases := []struct {
		rule, url string
		want      bool
	}{
		{"WebFetch(domain:example.com)", "https://example.com/a", true},
		{"WebFetch(domain:example.com)", "https://api.example.com/a", false},
		{"WebFetch(domain:example.com)", "https://example.com.", true},
		{"WebFetch(domain:*.example.com)", "https://api.example.com/a", true},
		{"WebFetch(domain:*.example.com)", "https://a.b.example.com/a", true},
		{"WebFetch(domain:*.example.com)", "https://example.com/a", false},
		{"WebFetch(domain:*)", "https://evil.example/a", true},
		{"WebFetch(domain:example.*)", "https://example.org/a", true},
		{"WebFetch(domain:example.*)", "https://example.evil.com/a", false},
		{"WebFetch", "https://anywhere.example", true},
	}
	for _, tc := range cases {
		if got := MatchWebFetch(ParseRule(tc.rule), tc.url); got != tc.want {
			t.Errorf("%s %s = %v want %v", tc.rule, tc.url, got, tc.want)
		}
	}
}

func TestPathTable(t *testing.T) {
	const cwd = "/repo"
	cases := []struct {
		rule, file, behavior string
		want                 bool
	}{
		{"Edit(src/**)", "/repo/src/app.ts", "allow", true},
		{"Edit(src/**)", "/repo/vendor/pkg/src/lib.js", "allow", false},
		{"Edit(src/**)", "/repo/src/app.ts", "deny", true},
		{"Edit(src/**)", "/repo/vendor/pkg/src/lib.js", "deny", true},
		{"Edit(/src/**)", "/repo/src/app.ts", "allow", true},
		{"Edit(/src/**)", "/repo/vendor/pkg/src/lib.js", "allow", false},
		{"Edit(**/src/**)", "/repo/vendor/pkg/src/lib.js", "allow", true},
		{"Read(.env)", "/repo/.env", "deny", true},
		{"Read(.env)", "/repo/pkg/.env", "deny", true},
		{"Read(./.env)", "/repo/.env", "deny", true},
		{"Read(~/.ssh/**)", "/home/ada/.ssh/id_rsa", "deny", true},
		{"Read(~/.ssh/**)", "/repo/.ssh/id_rsa", "deny", false},
	}
	for _, tc := range cases {
		r := ParseRule(tc.rule)
		r.Behavior = tc.behavior
		if got := MatchPath(r, tc.file, "/home/ada", cwd); got != tc.want {
			t.Errorf("%s (%s) %s = %v want %v", tc.rule, tc.behavior, tc.file, got, tc.want)
		}
	}
}
