package model

type Rule struct {
	Type       string
	Handler    string
	Invert     bool
	MatchType  string
	MatchValue []interface{}
}

type Evidence struct {
	Name   string
	Offset string
}
