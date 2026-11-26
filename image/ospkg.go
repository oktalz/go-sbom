package image

import (
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/oktalz/go-sbom/packages"
)

// osPackages lists the installed apk, dpkg and rpm packages, and whether a package database was found.
func (s *scan) osPackages() ([]packages.Package, bool, error) {
	apk := s.read(apkDB)
	if apk == nil {
		apk = s.read(apkDBUsr)
	}
	status := s.read(dpkgStatus)
	found := apk != nil || status != nil
	out := parseAPK(apk)
	dpkg := parseDpkg(status)
	for _, file := range slices.Sorted(maps.Keys(s.files)) {
		if strings.HasPrefix(file, dpkgStatusD) {
			found = true
			dpkg = append(dpkg, parseDpkg(s.files[file])...)
		}
	}
	for i := range dpkg {
		dpkg[i].License = debianLicense(s.read(docDir + dpkg[i].Path + "/copyright"))
	}
	rpm, rpmFound, err := s.rpmPackages()
	if err != nil {
		return nil, true, err
	}
	out = append(out, dpkg...)
	return append(out, rpm...), found || rpmFound, nil
}

// parseOSRelease returns the distro ID and "ID-VERSION_ID" of an os-release file.
func parseOSRelease(data []byte) (id, distro string) {
	var version string
	for line := range strings.Lines(string(data)) {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			id = v
		case "VERSION_ID":
			version = v
		}
	}
	if id == "" || version == "" {
		return id, id
	}
	return id, id + "-" + version
}

// parseAPK reads an apk installed database: blank-line separated "K:value" stanzas.
func parseAPK(data []byte) []packages.Package {
	var out []packages.Package
	var cur packages.Package
	flush := func() {
		if cur.Path != "" {
			cur.Type = packages.TypeAPK
			out = append(out, cur)
		}
		cur = packages.Package{}
	}
	for line := range strings.Lines(string(data)) {
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			flush()
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok || len(k) != 1 {
			continue
		}
		switch k {
		case "P":
			cur.Path = v
		case "V":
			cur.Version = v
		case "A":
			cur.Arch = v
		case "L":
			cur.License = v
		}
	}
	flush()
	return out
}

// parseDpkg reads dpkg status stanzas. A stanza without Status (distroless status.d) counts as installed.
func parseDpkg(data []byte) []packages.Package {
	var out []packages.Package
	for _, f := range stanzas(data) {
		if f["package"] == "" {
			continue
		}
		if status := strings.Fields(f["status"]); len(status) > 0 && status[len(status)-1] != "installed" {
			continue
		}
		out = append(out, packages.Package{
			Type:    packages.TypeDeb,
			Path:    f["package"],
			Version: f["version"],
			Arch:    f["architecture"],
		})
	}
	return out
}

// stanzas splits RFC 822 data at blank lines into fields keyed by lower-cased
// name. Only the first line of each field is kept.
func stanzas(data []byte) []map[string]string {
	text := strings.TrimPrefix(string(data), "\ufeff")
	var out []map[string]string
	cur := map[string]string{}
	for line := range strings.Lines(text) {
		switch {
		case strings.TrimSpace(line) == "":
			if len(cur) > 0 {
				out = append(out, cur)
				cur = map[string]string{}
			}
		case line[0] == ' ' || line[0] == '\t':
			// continuation line
		default:
			if k, v, ok := strings.Cut(line, ":"); ok {
				cur[strings.ToLower(k)] = strings.TrimSpace(v)
			}
		}
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// gplRe matches Debian (GPL-2+) and old Fedora (GPLv2+) GNU license names.
var gplRe = regexp.MustCompile(`(?i)^(A?GPL|LGPL|GFDL)-?v?([0-9])(\.[0-9])?(\+)?$`)

// licenseNames maps lower-cased Debian and old Fedora license names to SPDX ids.
var licenseNames = map[string]string{
	"expat":        "MIT",
	"gpl+":         "GPL-1.0-or-later",
	"mplv1.1":      "MPL-1.1",
	"mplv2.0":      "MPL-2.0",
	"bsd-2-clause": "BSD-2-Clause",
	"bsd-3-clause": "BSD-3-Clause",
	"bsd-4-clause": "BSD-4-Clause",
	"zlib":         "Zlib",
}

// debianLicense joins the licenses of a machine-readable (DEP-5) copyright
// file into one expression. Other files give "Unknown".
// Only the header and Files stanzas count: standalone License stanzas hold texts,
// and debian/* files are packaging, not part of the binary package.
func debianLicense(data []byte) string {
	all := stanzas(data)
	if len(all) == 0 || !strings.Contains(all[0]["format"], "copyright-format") {
		return "Unknown"
	}
	var exprs []string
	for i, f := range all {
		files, isFiles := f["files"]
		if (i > 0 && !isFiles) || packagingOnly(files) {
			continue
		}
		if e := debianExpr(f["license"]); e != "" && !slices.Contains(exprs, e) {
			exprs = append(exprs, e)
		}
	}
	switch len(exprs) {
	case 0:
		return "Unknown"
	case 1:
		return exprs[0]
	}
	for i, e := range exprs {
		if strings.Contains(e, " OR ") {
			exprs[i] = "(" + e + ")"
		}
	}
	return strings.Join(exprs, " AND ")
}

// packagingOnly reports whether a Files field names only debian/ paths.
func packagingOnly(files string) bool {
	patterns := strings.Fields(files)
	for _, p := range patterns {
		if !strings.HasPrefix(p, "debian/") {
			return false
		}
	}
	return len(patterns) > 0
}

// debianExpr converts a DEP-5 license expression ("GPL-2+ or Artistic") to SPDX form.
// A comma separates groups: "A or B, and C" is "(A OR B) AND C".
func debianExpr(v string) string {
	parts := strings.Split(v, ",")
	if len(parts) == 1 {
		return licenseTokens(v)
	}
	var out []string
	for i, part := range parts {
		expr := licenseTokens(part)
		if i > 0 {
			if op, rest, ok := strings.Cut(expr, " "); ok && (op == "AND" || op == "OR") {
				out = append(out, op)
				expr = rest
			}
		}
		if strings.Contains(expr, " OR ") {
			expr = "(" + expr + ")"
		}
		if expr != "" {
			out = append(out, expr)
		}
	}
	return strings.Join(out, " ")
}

// licenseTokens maps names and operators; "with OpenSSL exception" becomes one
// exception token, so the expression stays parseable.
func licenseTokens(v string) string {
	tokens := strings.Fields(strings.NewReplacer("(", " ( ", ")", " ) ").Replace(v))
	var out []string
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		switch lower := strings.ToLower(t); lower {
		case "or", "and":
			out = append(out, strings.ToUpper(t))
		case "with":
			out = append(out, "WITH")
			if end := exceptionEnd(tokens, i+1); end > i+1 {
				out = append(out, strings.Join(tokens[i+1:end], "-"))
				i = end - 1
			}
		default:
			if id, ok := licenseNames[lower]; ok {
				t = id
			} else if m := gplRe.FindStringSubmatch(t); m != nil {
				t = gplID(m)
			}
			out = append(out, t)
		}
	}
	return strings.NewReplacer("( ", "(", " )", ")").Replace(strings.Join(out, " "))
}

// exceptionEnd returns the index after a multi-word exception name ending in
// "exception", or start when there is none.
func exceptionEnd(tokens []string, start int) int {
	for j := start; j < len(tokens); j++ {
		switch strings.ToLower(tokens[j]) {
		case "exception":
			return j + 1
		case "or", "and", "with":
			return start
		}
	}
	return start
}

// gplID builds the SPDX id from a gplRe match: GPL-2+ is GPL-2.0-or-later.
func gplID(m []string) string {
	minor, suffix := m[3], "-only"
	if minor == "" {
		minor = ".0"
	}
	if m[4] == "+" {
		suffix = "-or-later"
	}
	return strings.ToUpper(m[1]) + "-" + m[2] + minor + suffix
}
