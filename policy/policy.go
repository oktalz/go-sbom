// Package policy decides whether a module's license is allowed by a --check
// policy.
package policy

import (
	"strings"
)

// Permits reports whether license is allowed. license is either a name that
// appears in allowed as a whole (case-insensitively, e.g. "MIT" or
// "Company Proprietary") or an SPDX license expression:
//
//   - "A AND B" needs both A and B allowed (every license applies),
//   - "A OR B" needs at least one allowed (the user may pick),
//   - "A WITH E" is allowed if "A WITH E" or A alone is allowed (an
//     exception only adds permissions),
//   - parentheses group, and AND binds tighter than OR.
//
// A license that is neither listed nor a valid expression is not allowed.
func Permits(license string, allowed map[string]bool) bool {
	if listed(license, allowed) {
		return true
	}
	p := &parser{tokens: tokenize(license), allowed: allowed}
	ok, err := p.or()
	if err || p.pos != len(p.tokens) {
		return false
	}
	return ok
}

func listed(name string, allowed map[string]bool) bool {
	if allowed[name] {
		return true
	}
	for a := range allowed {
		if strings.EqualFold(a, name) {
			return true
		}
	}
	return false
}

func tokenize(s string) []string {
	s = strings.NewReplacer("(", " ( ", ")", " ) ").Replace(s)
	return strings.Fields(s)
}

// parser is a recursive-descent evaluator over the tokens of an expression.
// Each method returns whether its part is allowed and whether it failed to
// parse.
type parser struct {
	allowed map[string]bool
	tokens  []string
	pos     int
}

func (p *parser) peek() string {
	if p.pos < len(p.tokens) {
		return p.tokens[p.pos]
	}
	return ""
}

func (p *parser) operator(op string) bool {
	if strings.EqualFold(p.peek(), op) {
		p.pos++
		return true
	}
	return false
}

func (p *parser) or() (ok, failed bool) {
	ok, failed = p.and()
	for !failed && p.operator("OR") {
		var right bool
		right, failed = p.and()
		ok = ok || right
	}
	return ok, failed
}

func (p *parser) and() (ok, failed bool) {
	ok, failed = p.with()
	for !failed && p.operator("AND") {
		var right bool
		right, failed = p.with()
		ok = ok && right
	}
	return ok, failed
}

func (p *parser) with() (ok, failed bool) {
	if p.operator("(") {
		ok, failed = p.or()
		if failed || !p.operator(")") {
			return false, true
		}
		return ok, false
	}
	id, failed := p.id()
	if failed {
		return false, true
	}
	if !p.operator("WITH") {
		return listed(id, p.allowed), false
	}
	exception, failed := p.id()
	if failed {
		return false, true
	}
	return listed(id+" WITH "+exception, p.allowed) || listed(id, p.allowed), false
}

// id consumes a license or exception identifier.
func (p *parser) id() (string, bool) {
	tok := p.peek()
	switch strings.ToUpper(tok) {
	case "", "(", ")", "AND", "OR", "WITH":
		return "", true
	}
	p.pos++
	return tok, false
}
