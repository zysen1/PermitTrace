package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// OpenCodeRule is one pattern inside an OpenCode permission object.
// Later rules in the file override earlier ones when both match.
type OpenCodeRule struct {
	Permission string // bash, edit, webfetch, ...
	Pattern    string
	Action     string // allow, ask, deny
}

// ParseOpenCode extracts ordered permission rules from opencode.json bytes.
// A string value ("permission": "allow") becomes a single "*" rule.
// Object values keep source order; the last matching pattern wins.
func ParseOpenCode(data []byte) ([]OpenCodeRule, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var rules []OpenCodeRule
	if err := walkOpenCode(dec, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func walkOpenCode(dec *json.Decoder, rules *[]OpenCodeRule) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok || d != '{' {
		return fmt.Errorf("opencode config must be an object")
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := keyTok.(string)
		if key != "permission" {
			if err := skipValue(dec); err != nil {
				return err
			}
			continue
		}
		if err := readPermission(dec, "", rules); err != nil {
			return err
		}
	}
	_, err = dec.Token()
	return err
}

func readPermission(dec *json.Decoder, tool string, rules *[]OpenCodeRule) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch v := tok.(type) {
	case string:
		perm := tool
		if perm == "" {
			perm = "*"
		}
		*rules = append(*rules, OpenCodeRule{Permission: perm, Pattern: "*", Action: v})
		return nil
	case json.Delim:
		if v != '{' {
			return fmt.Errorf("permission must be a string or object")
		}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			k, _ := kt.(string)
			// Peek the next value kind by decoding into RawMessage via tokens.
			if tool == "" {
				// top-level permission key: tool name, or a global pattern when the value is a string action
				if err := readPermissionValue(dec, k, rules); err != nil {
					return err
				}
			} else {
				action, err := readString(dec)
				if err != nil {
					return err
				}
				*rules = append(*rules, OpenCodeRule{Permission: tool, Pattern: k, Action: action})
			}
		}
		_, err = dec.Token()
		return err
	default:
		return fmt.Errorf("unexpected permission token %T", tok)
	}
}

func readPermissionValue(dec *json.Decoder, key string, rules *[]OpenCodeRule) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch v := tok.(type) {
	case string:
		// "bash": "allow"  OR  "*": "ask" at the top
		*rules = append(*rules, OpenCodeRule{Permission: key, Pattern: "*", Action: v})
		return nil
	case json.Delim:
		if v != '{' {
			return fmt.Errorf("permission %s must be a string or object", key)
		}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			pat, _ := kt.(string)
			action, err := readString(dec)
			if err != nil {
				return err
			}
			*rules = append(*rules, OpenCodeRule{Permission: key, Pattern: pat, Action: action})
		}
		_, err = dec.Token()
		return err
	default:
		return fmt.Errorf("permission %s has unexpected type %T", key, tok)
	}
}

func readString(dec *json.Decoder) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", err
	}
	s, ok := tok.(string)
	if !ok {
		return "", fmt.Errorf("expected string, got %T", tok)
	}
	return s, nil
}

func skipValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{', '[':
		for dec.More() {
			if d == '{' {
				if _, err := dec.Token(); err != nil {
					return err
				}
			}
			if err := skipValue(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	default:
		return fmt.Errorf("unexpected delim %s", d)
	}
}

// DecideOpenCode returns the action of the last matching rule for permission
// and input. input is the command, path, or URL the tool will see.
// An empty result means no rule matched.
func DecideOpenCode(rules []OpenCodeRule, permission, input string) string {
	action := ""
	for _, r := range rules {
		if r.Permission != "*" && r.Permission != permission {
			continue
		}
		if openCodeMatch(r.Pattern, input) {
			action = r.Action
		}
	}
	return action
}

// openCodeMatch uses * (any length) and ? (one character).
func openCodeMatch(pattern, input string) bool {
	if pattern == "*" {
		return true
	}
	return globQuestion(pattern, input)
}

func globQuestion(pattern, s string) bool {
	for {
		if pattern == "" {
			return s == ""
		}
		switch pattern[0] {
		case '*':
			pattern = pattern[1:]
			if pattern == "" {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if globQuestion(pattern, s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if s == "" {
				return false
			}
			pattern = pattern[1:]
			s = s[1:]
		default:
			if s == "" || s[0] != pattern[0] {
				return false
			}
			pattern = pattern[1:]
			s = s[1:]
		}
	}
}

// NormalizeOpenCodePermission maps Claude tool names onto OpenCode keys.
func NormalizeOpenCodePermission(tool string) string {
	switch strings.ToLower(tool) {
	case "bash", "powershell":
		return "bash"
	case "read":
		return "read"
	case "edit", "write", "notebookedit":
		return "edit"
	case "webfetch":
		return "webfetch"
	default:
		return strings.ToLower(tool)
	}
}
