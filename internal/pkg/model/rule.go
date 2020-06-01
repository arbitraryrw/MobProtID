package model

type Rule struct {
	Name       string
	Type       string
	Handler    string
	Invert     bool
	MatchType  string
	MatchValue []interface{}
}

type Evidence struct {
	File     string
	RuleName string
	Name     string
	Offset   string
}

type RuleResult struct {
	Match       bool
	Evidence    []Evidence
	RuleName    string
	RuleID      string
	Description string
}
