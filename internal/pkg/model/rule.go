package model

type Rule struct {
	Type       string
	Handler    string
	MatchType  string
	MatchValue []interface{}
}
