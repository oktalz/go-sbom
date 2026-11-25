package policy

import "testing"

func TestPermits(t *testing.T) {
	allowed := map[string]bool{
		"MIT":                 true,
		"Apache-2.0":          true,
		"BSD-3-Clause":        true,
		"Company Proprietary": true,
		"GPL-2.0-only WITH Classpath-exception-2.0": true,
	}
	tests := []struct {
		license string
		want    bool
	}{
		{"MIT", true},
		{"mit", true},
		{"GPL-3.0-only", false},
		{"Unknown", false},
		{"", false},
		{"Company Proprietary", true}, // free-form name listed as a whole
		{"Company Internal", false},

		{"MIT AND Apache-2.0", true},
		{"MIT AND GPL-3.0-only", false}, // every license must be allowed
		{"GPL-3.0-only OR MIT", true},   // one choice is enough
		{"GPL-3.0-only OR LGPL-3.0-only", false},
		{"MIT and apache-2.0", true}, // operators are case-insensitive
		{"(MIT OR GPL-3.0-only) AND BSD-3-Clause", true},
		{"(MIT OR GPL-3.0-only) AND LGPL-3.0-only", false},
		{"MIT OR GPL-3.0-only AND LGPL-3.0-only", true}, // AND binds tighter: MIT OR (GPL AND LGPL)
		{"GPL-3.0-only AND MIT OR BSD-3-Clause", true},

		{"Apache-2.0 WITH LLVM-exception", true},            // base license allowed
		{"GPL-2.0-only WITH Classpath-exception-2.0", true}, // listed as a whole
		{"(GPL-2.0-only WITH Classpath-exception-2.0) AND MIT", true},
		{"GPL-2.0-only WITH Autoconf-exception-2.0", false},

		{"MIT AND", false}, // malformed expressions are not allowed
		{"(MIT", false},
		{"MIT Apache-2.0", false},
		{"MIT WITH", false},
		{"AND MIT", false},
	}
	for _, tt := range tests {
		if got := Permits(tt.license, allowed); got != tt.want {
			t.Errorf("Permits(%q) = %v, want %v", tt.license, got, tt.want)
		}
	}
}

func TestPermitsListedExpression(t *testing.T) {
	// v0.1.0 compared whole strings; an allowed entry that is itself an
	// expression keeps working.
	allowed := map[string]bool{"MIT OR Apache-2.0": true}
	if !Permits("MIT OR Apache-2.0", allowed) {
		t.Error("an expression listed verbatim should be allowed")
	}
	if Permits("MIT", allowed) {
		t.Error("MIT alone is not in the list")
	}
}
