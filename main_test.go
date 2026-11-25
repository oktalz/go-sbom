package main

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/oktalz/go-sbom/packages"
)

func TestSortedKeys(t *testing.T) {
	m := map[string]bool{
		"MIT":          true,
		"Apache-2.0":   true,
		"BSD-3-Clause": true,
		"ISC":          true,
	}

	keys := sortedKeys(m)

	expected := []string{"Apache-2.0", "BSD-3-Clause", "ISC", "MIT"}
	if len(keys) != len(expected) {
		t.Fatalf("len = %d, want %d", len(keys), len(expected))
	}
	for i, k := range keys {
		if k != expected[i] {
			t.Errorf("keys[%d] = %q, want %q", i, k, expected[i])
		}
	}
}

func TestSortedKeysEmpty(t *testing.T) {
	keys := sortedKeys(map[string]bool{})
	if len(keys) != 0 {
		t.Errorf("expected empty slice, got %v", keys)
	}
}

func TestWriteJUnitAllPassing(t *testing.T) {
	info := &packages.Info{
		Deps: []packages.Package{
			{Path: "github.com/google/uuid", Version: "v1.6.0", License: "BSD-3-Clause"},
			{Path: "github.com/pkg/errors", Version: "v0.9.1", License: "BSD-2-Clause"},
		},
	}

	allowed := map[string]bool{
		"BSD-3-Clause": true,
		"BSD-2-Clause": true,
		"MIT":          true,
	}

	dir := t.TempDir()
	junitFile := filepath.Join(dir, "report.xml")

	writeJUnit(info, nil, allowed, junitFile)

	data, err := os.ReadFile(junitFile)
	if err != nil {
		t.Fatal(err)
	}

	// Verify valid XML
	var result struct {
		XMLName xml.Name `xml:"testsuites"`
	}
	if err := xml.Unmarshal(data, &result); err != nil {
		t.Fatalf("invalid XML: %v", err)
	}

	content := string(data)
	// Should contain test case names
	if !contains(content, "github.com/google/uuid@v1.6.0") {
		t.Error("JUnit report missing uuid test case")
	}
	if !contains(content, "github.com/pkg/errors@v0.9.1") {
		t.Error("JUnit report missing errors test case")
	}
	// No failures
	if contains(content, "<failure") {
		t.Error("JUnit report should not have failures when all passing")
	}
}

func TestWriteJUnitWithViolations(t *testing.T) {
	info := &packages.Info{
		Deps: []packages.Package{
			{Path: "github.com/google/uuid", Version: "v1.6.0", License: "BSD-3-Clause"},
			{Path: "github.com/bad/pkg", Version: "v1.0.0", License: "GPL-3.0"},
		},
	}

	allowed := map[string]bool{
		"BSD-3-Clause": true,
		"MIT":          true,
	}

	violations := []packages.Package{
		{Path: "github.com/bad/pkg", Version: "v1.0.0", License: "GPL-3.0"},
	}

	dir := t.TempDir()
	junitFile := filepath.Join(dir, "report.xml")

	writeJUnit(info, violations, allowed, junitFile)

	data, err := os.ReadFile(junitFile)
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	// Should contain failure for bad/pkg
	if !contains(content, "github.com/bad/pkg") {
		t.Error("JUnit report missing bad/pkg")
	}
	if !contains(content, "failure") {
		t.Error("JUnit report should have failure for violation")
	}
}

func TestWriteJUnitWithReplace(t *testing.T) {
	info := &packages.Info{
		Deps: []packages.Package{
			{
				Path:    "github.com/old/pkg",
				Version: "v1.0.0",
				License: "MIT",
				Replace: &packages.Package{
					Path:    "github.com/new/pkg",
					Version: "v2.0.0",
					License: "Apache-2.0",
				},
			},
		},
	}

	allowed := map[string]bool{
		"Apache-2.0": true,
	}

	dir := t.TempDir()
	junitFile := filepath.Join(dir, "report.xml")

	writeJUnit(info, nil, allowed, junitFile)

	data, err := os.ReadFile(junitFile)
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	// Should use replacement path
	if !contains(content, "github.com/new/pkg@v2.0.0") {
		t.Error("JUnit report should use replacement package path")
	}
}

func TestWriteJUnitInvalidPath(_ *testing.T) {
	info := &packages.Info{
		Deps: []packages.Package{
			{Path: "github.com/google/uuid", Version: "v1.6.0", License: "BSD-3-Clause"},
		},
	}

	// Write to a non-existent directory - should not panic, just print warning
	writeJUnit(info, nil, map[string]bool{"BSD-3-Clause": true}, "/nonexistent/dir/report.xml")
}

func TestExcludeDeps(t *testing.T) {
	info := &packages.Info{
		Deps: []packages.Package{
			{Path: "github.com/google/uuid", Version: "v1.6.0"},
			{Path: "github.com/pkg/errors", Version: "v0.9.1"},
			{Path: "github.com/stretchr/testify", Version: "v1.9.0"},
		},
	}

	excludeDeps(info, "github.com/pkg/errors")

	if len(info.Deps) != 2 {
		t.Fatalf("expected 2 deps after exclude, got %d", len(info.Deps))
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/pkg/errors" {
			t.Error("excluded package should not be present")
		}
	}
}

func TestExcludeDepsMultiple(t *testing.T) {
	info := &packages.Info{
		Deps: []packages.Package{
			{Path: "github.com/google/uuid", Version: "v1.6.0"},
			{Path: "github.com/pkg/errors", Version: "v0.9.1"},
			{Path: "github.com/stretchr/testify", Version: "v1.9.0"},
			{Path: "company.com/internal/pkg", Version: "v0.1.0"},
		},
	}

	excludeDeps(info, "github.com/pkg/errors,company.com/internal/pkg")

	if len(info.Deps) != 2 {
		t.Fatalf("expected 2 deps after exclude, got %d", len(info.Deps))
	}
	paths := make(map[string]bool)
	for _, dep := range info.Deps {
		paths[dep.Path] = true
	}
	if !paths["github.com/google/uuid"] {
		t.Error("uuid should remain")
	}
	if !paths["github.com/stretchr/testify"] {
		t.Error("testify should remain")
	}
}

func TestExcludeDepsWithReplace(t *testing.T) {
	info := &packages.Info{
		Deps: []packages.Package{
			{Path: "github.com/google/uuid", Version: "v1.6.0"},
			{
				Path:    "github.com/old/pkg",
				Version: "v1.0.0",
				Replace: &packages.Package{
					Path:    "company.com/fork/pkg",
					Version: "v2.0.0",
				},
			},
		},
	}

	// Exclude by replacement path
	excludeDeps(info, "company.com/fork/pkg")

	if len(info.Deps) != 1 {
		t.Fatalf("expected 1 dep after exclude, got %d", len(info.Deps))
	}
	if info.Deps[0].Path != "github.com/google/uuid" {
		t.Errorf("remaining dep = %q, want uuid", info.Deps[0].Path)
	}
}

func TestExcludeDepsWithSpaces(t *testing.T) {
	info := &packages.Info{
		Deps: []packages.Package{
			{Path: "github.com/google/uuid", Version: "v1.6.0"},
			{Path: "github.com/pkg/errors", Version: "v0.9.1"},
		},
	}

	excludeDeps(info, " github.com/pkg/errors , github.com/nonexistent ")

	if len(info.Deps) != 1 {
		t.Fatalf("expected 1 dep after exclude, got %d", len(info.Deps))
	}
}

func TestExcludeDepsNoneMatch(t *testing.T) {
	info := &packages.Info{
		Deps: []packages.Package{
			{Path: "github.com/google/uuid", Version: "v1.6.0"},
			{Path: "github.com/pkg/errors", Version: "v0.9.1"},
		},
	}

	excludeDeps(info, "github.com/nonexistent")

	if len(info.Deps) != 2 {
		t.Fatalf("expected 2 deps when exclude matches nothing, got %d", len(info.Deps))
	}
}

func TestExcludeDepsAll(t *testing.T) {
	info := &packages.Info{
		Deps: []packages.Package{
			{Path: "github.com/google/uuid", Version: "v1.6.0"},
			{Path: "github.com/pkg/errors", Version: "v0.9.1"},
		},
	}

	excludeDeps(info, "github.com/google/uuid,github.com/pkg/errors")

	if len(info.Deps) != 0 {
		t.Fatalf("expected 0 deps after excluding all, got %d", len(info.Deps))
	}
}

func TestApplyLicenceOverrides(t *testing.T) {
	info := &packages.Info{
		Main: packages.Package{Path: "github.com/example/app", Version: "v1.0.0"},
		Deps: []packages.Package{
			{Path: "github.com/google/uuid", Version: "v1.6.0", License: "Unknown"},
			{Path: "github.com/pkg/errors", Version: "v0.9.1", License: "BSD-2-Clause"},
		},
	}

	applyLicenceOverrides(info, []string{"github.com/google/uuid:BSD-3-Clause"})

	if info.Deps[0].License != "BSD-3-Clause" {
		t.Errorf("expected BSD-3-Clause, got %q", info.Deps[0].License)
	}
	// Unmatched dep should keep original license
	if info.Deps[1].License != "BSD-2-Clause" {
		t.Errorf("expected BSD-2-Clause, got %q", info.Deps[1].License)
	}
}

func TestApplyLicenceOverridesReplace(t *testing.T) {
	info := &packages.Info{
		Main: packages.Package{Path: "github.com/example/app", Version: "v1.0.0"},
		Deps: []packages.Package{
			{
				Path:    "github.com/old/pkg",
				Version: "v1.0.0",
				License: "MIT",
				Replace: &packages.Package{
					Path:    "github.com/new/pkg",
					Version: "v2.0.0",
					License: "Unknown",
				},
			},
		},
	}

	applyLicenceOverrides(info, []string{"github.com/new/pkg:Apache-2.0"})

	if info.Deps[0].Replace.License != "Apache-2.0" {
		t.Errorf("expected Apache-2.0 on replace, got %q", info.Deps[0].Replace.License)
	}
}

func TestApplyLicenceOverridesMain(t *testing.T) {
	info := &packages.Info{
		Main: packages.Package{Path: "github.com/example/app", Version: "v1.0.0", License: "Unknown"},
		Deps: []packages.Package{
			{Path: "github.com/google/uuid", Version: "v1.6.0", License: "BSD-3-Clause"},
		},
	}

	applyLicenceOverrides(info, []string{"github.com/example/app:Apache-2.0"})

	if info.Main.License != "Apache-2.0" {
		t.Errorf("expected Apache-2.0 on main, got %q", info.Main.License)
	}
	// Dep should be unchanged
	if info.Deps[0].License != "BSD-3-Clause" {
		t.Errorf("expected BSD-3-Clause, got %q", info.Deps[0].License)
	}
}

func TestApplyLicenceOverridesNoMatch(t *testing.T) {
	info := &packages.Info{
		Main: packages.Package{Path: "github.com/example/app", Version: "v1.0.0"},
		Deps: []packages.Package{
			{Path: "github.com/google/uuid", Version: "v1.6.0", License: "BSD-3-Clause"},
		},
	}

	applyLicenceOverrides(info, []string{"github.com/nonexistent:MIT"})

	if info.Deps[0].License != "BSD-3-Clause" {
		t.Errorf("expected BSD-3-Clause unchanged, got %q", info.Deps[0].License)
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && // avoid trivial matches
		len(s) >= len(substr) &&
		findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestExcludeDepsPrefixAndGlob(t *testing.T) {
	info := &packages.Info{
		Deps: []packages.Package{
			{Path: "company.com/internal/a"},
			{Path: "company.com/internal/b/c"},
			{Path: "company.com/internalx"},
			{Path: "git.corp.example.com/team/x"},
			{Path: "github.com/pkg/errors"},
		},
	}
	excludeDeps(info, "company.com/internal, *.corp.example.com")
	var got []string
	for _, d := range info.Deps {
		got = append(got, d.Path)
	}
	want := []string{"company.com/internalx", "github.com/pkg/errors"}
	if !slices.Equal(got, want) {
		t.Errorf("remaining deps = %v, want %v", got, want)
	}
}

func TestFindViolations(t *testing.T) {
	deps := []packages.Package{
		{Path: "a", Version: "v1.0.0", License: "MIT"},
		{Path: "b", Version: "v1.0.0", License: "MIT AND Apache-2.0"},
		{Path: "c", Version: "v1.0.0", License: "MIT AND GPL-3.0-only"},
		{Path: "d", Version: "v1.0.0", License: "GPL-3.0-only OR MIT"},
		{Path: "e", Version: "v1.0.0", License: "Unknown"},
		{Path: "f", Version: "v1.0.0", Replace: &packages.Package{Path: "g", Version: "v1.0.0", License: "Apache-2.0"}},
	}
	allowed := map[string]bool{"MIT": true, "Apache-2.0": true}

	var got []string
	for _, v := range findViolations(deps, allowed) {
		got = append(got, v.Path)
	}
	if want := []string{"c", "e"}; !slices.Equal(got, want) {
		t.Errorf("violations = %v, want %v", got, want)
	}
}

func replacedDeps() []packages.Package {
	return []packages.Package{
		{Path: "github.com/google/uuid", Version: "v1.6.0"},
		// local replacement: the effective path is a directory
		{Path: "corp.example/auth", Version: "v0.0.0", Replace: &packages.Package{Path: "./auth"}},
		// replaced by a fork
		{Path: "github.com/orig/lib", Version: "v1.0.0", Replace: &packages.Package{Path: "github.com/fork/lib", Version: "v1.2.3"}},
	}
}

func TestExcludeDepsMatchesModulePathOfReplaced(t *testing.T) {
	tests := []struct {
		pattern string
		want    []string // remaining module paths
	}{
		{"corp.example", []string{"github.com/google/uuid", "github.com/orig/lib"}},
		{"./auth", []string{"github.com/google/uuid", "github.com/orig/lib"}},
		{"github.com/orig", []string{"github.com/google/uuid", "corp.example/auth"}},
		{"github.com/fork/lib", []string{"github.com/google/uuid", "corp.example/auth"}},
		{"*.example,github.com/orig/lib", []string{"github.com/google/uuid"}},
	}
	for _, tt := range tests {
		info := &packages.Info{Deps: replacedDeps()}
		excludeDeps(info, tt.pattern)
		var got []string
		for _, d := range info.Deps {
			got = append(got, d.Path)
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("exclude %q: remaining %v, want %v", tt.pattern, got, tt.want)
		}
	}
}

func TestApplyLicenceOverridesModulePathOfReplaced(t *testing.T) {
	info := &packages.Info{Deps: replacedDeps()}
	applyLicenceOverrides(info, []string{"corp.example/auth:LicenseRef-Corp", "github.com/orig/lib:MIT"})
	if got := info.Deps[1].Replace.License; got != "LicenseRef-Corp" {
		t.Errorf("local replacement license = %q, want LicenseRef-Corp (set by module path)", got)
	}
	if got := info.Deps[2].Replace.License; got != "MIT" {
		t.Errorf("fork license = %q, want MIT (set by original module path)", got)
	}
	if info.Deps[1].License != "" || info.Deps[2].License != "" {
		t.Error("the license belongs on the replacement, not the original module")
	}

	// Both paths given: the replacement's path wins.
	info = &packages.Info{Deps: replacedDeps()}
	applyLicenceOverrides(info, []string{"github.com/orig/lib:MIT", "github.com/fork/lib:Apache-2.0"})
	if got := info.Deps[2].Replace.License; got != "Apache-2.0" {
		t.Errorf("fork license = %q, want Apache-2.0 (replacement path wins)", got)
	}
}
