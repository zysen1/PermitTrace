package bench

// RepoFile is one file in a scenario's mini-repository.
type RepoFile struct {
	Path      string
	Body      string
	Source    string
	Locator   string
	NoSegment bool
}

// Scenario is one AllowRuleBench-mini case. It does not store the expected
// decision: that is computed, then compared with the planted source and the
// task commands.
type Scenario struct {
	ID            string
	Split         string
	Kind          string
	Carrier       string
	PlantedSource string
	User          string
	Files         []RepoFile
	Tool          string
	Command       string
	FilePath      string
	URL           string
	RuleTool      string
	RuleSpec      string
	Destination   string
	Task          []string
	Note          string
}
