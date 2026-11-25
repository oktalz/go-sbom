package output

import (
	_ "embed"
	"regexp"
	"strings"
)

// Lists from https://github.com/spdx/license-list-data, deprecated IDs included.
// To refresh, regenerate the files from json/licenses.json and json/exceptions.json.
var (
	//go:embed spdx-licenses.txt
	spdxLicenseList string
	//go:embed spdx-exceptions.txt
	spdxExceptionList string

	spdxLicenseIDs   = parseIDList(spdxLicenseList)
	spdxExceptionIDs = parseIDList(spdxExceptionList)

	licenseRefRe = regexp.MustCompile(`^(DocumentRef-[A-Za-z0-9.-]+:)?LicenseRef-[A-Za-z0-9.-]+$`)
	invalidRefRe = regexp.MustCompile(`[^A-Za-z0-9.-]+`)
)

// parseIDList maps the lower-cased form of each ID to its canonical spelling.
func parseIDList(list string) map[string]string {
	m := make(map[string]string)
	for line := range strings.SplitSeq(list, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m[strings.ToLower(line)] = line
	}
	return m
}

// canonicalSPDX checks whether license is a valid SPDX license expression made
// of known SPDX license IDs, LicenseRef- identifiers and known exceptions.
// It returns the expression with IDs in their canonical spelling, and whether
// the expression is a single identifier (no operators).
func canonicalSPDX(license string) (expr string, single, ok bool) {
	license = strings.NewReplacer("(", " ( ", ")", " ) ").Replace(license)
	tokens := strings.Fields(license)
	if len(tokens) == 0 {
		return "", false, false
	}

	out := make([]string, 0, len(tokens))
	depth := 0
	expectOperand := true
	afterWith := false
	for _, tok := range tokens {
		upper := strings.ToUpper(tok)
		switch {
		case tok == "(":
			if !expectOperand {
				return "", false, false
			}
			depth++
			out = append(out, tok)
		case tok == ")":
			if expectOperand || depth == 0 {
				return "", false, false
			}
			depth--
			out = append(out, tok)
		case upper == "AND" || upper == "OR" || upper == "WITH":
			if expectOperand {
				return "", false, false
			}
			expectOperand = true
			afterWith = upper == "WITH"
			out = append(out, upper)
		default:
			if !expectOperand {
				return "", false, false
			}
			id, valid := canonicalID(tok, afterWith)
			if !valid {
				return "", false, false
			}
			out = append(out, id)
			expectOperand = false
			afterWith = false
		}
	}
	if expectOperand || depth != 0 {
		return "", false, false
	}

	expr = strings.Join(out, " ")
	expr = strings.ReplaceAll(strings.ReplaceAll(expr, "( ", "("), " )", ")")
	return expr, len(out) == 1, true
}

func canonicalID(tok string, exception bool) (string, bool) {
	if exception {
		id, ok := spdxExceptionIDs[strings.ToLower(tok)]
		return id, ok
	}
	if licenseRefRe.MatchString(tok) {
		return tok, true
	}
	base, plus := strings.CutSuffix(tok, "+")
	id, ok := spdxLicenseIDs[strings.ToLower(base)]
	if plus {
		id += "+"
	}
	return id, ok
}

// licenseRef turns an arbitrary license name into a valid SPDX LicenseRef-.
func licenseRef(name string) string {
	s := strings.Trim(invalidRefRe.ReplaceAllString(name, "-"), "-")
	if s == "" {
		s = "unnamed"
	}
	return "LicenseRef-" + s
}
