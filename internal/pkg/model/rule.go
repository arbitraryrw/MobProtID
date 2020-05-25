package model

type Rule struct {
	Type       string
	Handler    string
	Invert     bool
	MatchType  string
	MatchValue []interface{}
}
