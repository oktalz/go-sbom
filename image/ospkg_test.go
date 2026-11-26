package image

import (
	"slices"
	"testing"

	"github.com/oktalz/go-sbom/packages"
)

func TestWanted(t *testing.T) {
	for p, want := range map[string]bool{
		"/etc/os-release":                       true,
		"/usr/lib/os-release":                   true,
		"/lib/apk/db/installed":                 true,
		"/var/lib/dpkg/status":                  true,
		"/var/lib/dpkg/status.d/tzdata":         true,
		"/var/lib/dpkg/status.d/tzdata.md5sums": false,
		"/var/lib/dpkg/status.d/sub/x":          false,
		"/usr/share/doc/libc6/copyright":        true,
		"/usr/share/doc/libc6/changelog.gz":     false,
		"/usr/share/doc/copyright":              false,
		"/usr/share/doc/a/b/copyright":          false,
		"/usr/bin/app":                          false,
	} {
		if got := wanted(p); got != want {
			t.Errorf("wanted(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestParseOSRelease(t *testing.T) {
	tests := []struct {
		data, id, distro string
	}{
		{"ID=alpine\nVERSION_ID=3.20.3\n", "alpine", "alpine-3.20.3"},
		{"ID=\"debian\"\nVERSION_ID='12'\n", "debian", "debian-12"},
		{"# comment\nID=debian\nPRETTY_NAME=\"Debian trixie/sid\"\n", "debian", "debian"},
		{"", "", ""},
	}
	for _, tt := range tests {
		id, distro := parseOSRelease([]byte(tt.data))
		if id != tt.id || distro != tt.distro {
			t.Errorf("parseOSRelease(%q) = %q, %q; want %q, %q", tt.data, id, distro, tt.id, tt.distro)
		}
	}
}

func TestParseAPK(t *testing.T) {
	data := "P:musl\r\nV:1.2.5-r0\r\nA:x86_64\r\nL:MIT\r\n\r\n\n\nP:nolicense\nV:1\nbad line\nXY:ignored\n\nV:no-name\n"
	got := parseAPK([]byte(data))
	want := []packages.Package{
		{Type: packages.TypeAPK, Path: "musl", Version: "1.2.5-r0", Arch: "x86_64", License: "MIT"},
		{Type: packages.TypeAPK, Path: "nolicense", Version: "1"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("parseAPK = %+v\nwant %+v", got, want)
	}
	if got := parseAPK(nil); got != nil {
		t.Errorf("parseAPK(nil) = %+v", got)
	}
}

func TestParseDpkg(t *testing.T) {
	data := "\ufeffPackage: a\nStatus: install ok installed\nVersion: 1:2.0-1\nArchitecture: amd64\nDescription: x\n Package: not-a-field\n" +
		"\nPackage: b\nStatus: deinstall ok config-files\nVersion: 1\n" +
		"\nPackage: c\nStatus: install ok half-installed\n" +
		"\nPackage: d\nVersion: 3\n \t\npackage: e\n\n\n\nNo-Package: here\n"
	got := parseDpkg([]byte(data))
	want := []packages.Package{
		{Type: packages.TypeDeb, Path: "a", Version: "1:2.0-1", Arch: "amd64"},
		{Type: packages.TypeDeb, Path: "d", Version: "3"},
		{Type: packages.TypeDeb, Path: "e"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("parseDpkg = %+v\nwant %+v", got, want)
	}
}

func TestDebianLicense(t *testing.T) {
	const dep5 = "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n"
	tests := []struct {
		name, data, want string
	}{
		{"not DEP-5", "Copyright 1999 someone\nLicense: MIT\n", "Unknown"},
		{"no file", "", "Unknown"},
		{"no license field", dep5 + "Files: *\n", "Unknown"},
		{"single", dep5 + "\nFiles: *\nLicense: Expat\n", "MIT"},
		{"duplicates", dep5 + "\nFiles: a\nLicense: GPL-2+\n\nFiles: b\nLicense: GPL-2+\n", "GPL-2.0-or-later"},
		{"several", dep5 + "\nFiles: a\nLicense: GPL-2\n\nFiles: b\nLicense: bsd-3-clause\n", "GPL-2.0-only AND BSD-3-Clause"},
		{"or groups", dep5 + "\nFiles: a\nLicense: LGPL-2.1+\n\nFiles: b\nLicense: GPL-2+ or Artistic\n", "LGPL-2.1-or-later AND (GPL-2.0-or-later OR Artistic)"},
		{"comma", dep5 + "License: GPL-3+ or LGPL-3, and zlib\n", "(GPL-3.0-or-later OR LGPL-3.0-only) AND Zlib"},
		{"comma without or", dep5 + "License: MIT, and zlib\n", "MIT AND Zlib"},
		{"comma then or", dep5 + "License: Expat, and GPL-1+ or Artistic\n", "MIT AND (GPL-1.0-or-later OR Artistic)"},
		{"two commas", dep5 + "License: A or B, and C or D, and E\n", "(A OR B) AND (C OR D) AND E"},
		{"crlf", "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\r\nLicense: AGPL-3\r\n", "AGPL-3.0-only"},
		{"bom and lower-case field", "\ufeffFormat: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\nlicense: Expat\n", "MIT"},
		{"with exception", dep5 + "License: GPL-2+ with OpenSSL exception\n", "GPL-2.0-or-later WITH OpenSSL-exception"},
		{"with known id", dep5 + "License: GPL-2+ with Classpath-exception-2.0\n", "GPL-2.0-or-later WITH Classpath-exception-2.0"},
		{"packaging only", "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n\nFiles: *\nLicense: Expat\n\n" +
			"Files: debian/*\nLicense: GPL-2+\n\nLicense: GPL-2+\n text of the GPL\n", "MIT"},
		{"header license", "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\nLicense: Apache-2.0\n\nFiles: debian/*\nLicense: GPL-2+\n", "Apache-2.0"},
		{"standalone license only", dep5 + "\nLicense: MIT\n text\n", "Unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := debianLicense([]byte(tt.data)); got != tt.want {
				t.Errorf("debianLicense = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGPLID(t *testing.T) {
	for in, want := range map[string]string{
		"GPL-2":      "GPL-2.0-only",
		"GPL-2+":     "GPL-2.0-or-later",
		"GPL-2.0+":   "GPL-2.0-or-later",
		"lgpl-2.1":   "LGPL-2.1-only",
		"GFDL-1.3+":  "GFDL-1.3-or-later",
		"AGPL-3":     "AGPL-3.0-only",
		"GPL-2-only": "GPL-2-only", // not a Debian short name: kept
	} {
		if got := debianExpr(in); got != want {
			t.Errorf("debianExpr(%q) = %q, want %q", in, got, want)
		}
	}
}
