// Package report renders a decision as a terminal card and as one offline HTML file.
package report

import (
	_ "embed"
	"html/template"
	"strings"
	"time"

	"github.com/zysen1/PermitTrace/internal/engine"
	"github.com/zysen1/PermitTrace/internal/prov"
)

//go:embed template.html
var templateHTML string

// Hit is a provenance row safe for the template.
type Hit struct {
	Source  string
	Locator string
	Score   float64
	Excerpt string
}

// Witness is a blast-radius row.
type Witness struct {
	Command    string
	Detail     string
	Capability string
}

// View is the HTML model.
type View struct {
	Title        string
	Action       string
	Reason       string
	Risk         float64
	Trust        float64
	Capability   float64
	Scope        string
	ScopeWeight  float64
	Destination  string
	Current      string
	Capabilities []string
	Proposed     []string
	Synthesized  []string
	Hits         []Hit
	Witnesses    []Witness
	RingSession  string
	RingProject  string
	RingUser     string
	Generated    string
}

// Card is the terminal summary used by replay and demo.
func Card(res engine.Result) string {
	var b strings.Builder
	b.WriteString("PermitTrace  " + strings.ToUpper(res.Action) + "\n")
	b.WriteString(res.Reason)
	b.WriteByte('\n')
	if len(res.Witnesses) > 0 {
		w := res.Witnesses[0]
		b.WriteString("unlocks: " + w.Command)
		if w.Detail != "" {
			b.WriteString(" → " + one(w.Detail))
		}
		b.WriteString("  [" + w.Capability + "]\n")
	}
	if len(res.Attribution) > 0 {
		h := res.Attribution[0]
		loc := h.Segment.Locator
		if loc == "" {
			loc = h.Segment.Source
		}
		b.WriteString("induced by: " + loc + "\n")
	}
	if len(res.Synthesized) > 0 {
		b.WriteString("instead: ")
		for i, s := range res.Synthesized {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(s.String())
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// HTML renders the single-file report.
func HTML(title string, res engine.Result) ([]byte, error) {
	v := View{
		Title: title, Action: res.Action, Reason: res.Reason,
		Risk: res.Risk, Trust: res.Trust, Capability: res.Capability,
		Scope: res.Scope, ScopeWeight: res.ScopeWeight, Destination: res.Destination,
		Current: res.Current, Capabilities: res.Capabilities,
		RingSession: "#243044", RingProject: "#243044", RingUser: "#243044",
		Generated: time.Now().UTC().Format(time.RFC3339),
	}
	switch res.Scope {
	case "userSettings":
		v.RingUser = "#ff5d6c"
	case "projectSettings":
		v.RingProject = "#ffb020"
	case "localSettings":
		v.RingProject = "#7aa2f7"
	default:
		v.RingSession = "#3dd68c"
	}
	for _, r := range res.Proposed {
		v.Proposed = append(v.Proposed, r.String())
	}
	for _, r := range res.Synthesized {
		v.Synthesized = append(v.Synthesized, r.String())
	}
	for _, h := range res.Attribution {
		v.Hits = append(v.Hits, hitView(h))
	}
	for _, w := range res.Witnesses {
		v.Witnesses = append(v.Witnesses, Witness{Command: w.Command, Detail: one(w.Detail), Capability: w.Capability})
	}
	tpl, err := template.New("report").Parse(templateHTML)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	if err := tpl.Execute(&b, v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func hitView(h prov.Hit) Hit {
	return Hit{
		Source: h.Segment.Source, Locator: h.Segment.Locator, Score: h.Score,
		Excerpt: excerpt(h.Segment.Text, h.Segment.Locator),
	}
}

func excerpt(text, locator string) string {
	text = strings.TrimSpace(text)
	if line := lineOf(locator); line > 0 {
		lines := strings.Split(text, "\n")
		if line <= len(lines) {
			from := line - 2
			if from < 1 {
				from = 1
			}
			to := line + 1
			if to > len(lines) {
				to = len(lines)
			}
			var b strings.Builder
			for i := from; i <= to; i++ {
				mark := "  "
				if i == line {
					mark = "→ "
				}
				b.WriteString(mark)
				b.WriteString(strings.TrimRight(lines[i-1], "\r"))
				b.WriteByte('\n')
			}
			return strings.TrimRight(b.String(), "\n")
		}
	}
	if len(text) > 400 {
		return text[:400] + "…"
	}
	return text
}

func lineOf(locator string) int {
	i := strings.LastIndex(locator, ":")
	if i < 0 {
		return 0
	}
	n := 0
	for _, c := range locator[i+1:] {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func one(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if len(s) > 140 {
		return s[:140] + "…"
	}
	return s
}
