package output

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oktalz/go-sbom/packages"
)

func sampleInfo() *packages.Info {
	return &packages.Info{
		GoVersion: "go1.22.0",
		Path:      "github.com/example/myapp",
		Main: packages.Package{
			Path:    "github.com/example/myapp",
			Version: "v1.0.0",
			License: "Apache-2.0",
		},
		Deps: []packages.Package{
			{
				Path:    "github.com/pkg/errors",
				Version: "v0.9.1",
				License: "BSD-2-Clause",
			},
			{
				Path:        "github.com/google/uuid",
				Version:     "v1.6.0",
				License:     "BSD-3-Clause",
				LicenseLink: "https://github.com/google/uuid/blob/v1.6.0/LICENSE",
			},
			{
				Path:    "github.com/stretchr/testify",
				Version: "v1.9.0",
				License: "MIT",
			},
		},
	}
}

func sampleInfoWithReplace() *packages.Info {
	return &packages.Info{
		GoVersion: "go1.22.0",
		Path:      "github.com/example/myapp",
		Main: packages.Package{
			Path:    "github.com/example/myapp",
			Version: "v1.0.0",
		},
		Deps: []packages.Package{
			{
				Path:    "github.com/old/pkg",
				Version: "v1.0.0",
				License: "MIT",
				Replace: &packages.Package{
					Path:        "github.com/new/pkg",
					Version:     "v2.0.0",
					License:     "Apache-2.0",
					LicenseLink: "https://github.com/new/pkg/blob/v2.0.0/LICENSE",
				},
			},
			{
				Path:    "github.com/simple/dep",
				Version: "v0.1.0",
				License: "ISC",
			},
		},
	}
}

func TestSortDeps(t *testing.T) {
	info := &packages.Info{
		Deps: []packages.Package{
			{Path: "z-pkg", License: "MIT"},
			{Path: "a-pkg", License: "MIT"},
			{Path: "m-pkg", License: "Apache-2.0"},
			{Path: "b-pkg", License: "BSD-3-Clause"},
		},
	}

	sortDeps(info)

	expected := []struct {
		path    string
		license string
	}{
		{"m-pkg", "Apache-2.0"},
		{"b-pkg", "BSD-3-Clause"},
		{"a-pkg", "MIT"},
		{"z-pkg", "MIT"},
	}

	for i, exp := range expected {
		if info.Deps[i].Path != exp.path {
			t.Errorf("dep[%d].Path = %q, want %q", i, info.Deps[i].Path, exp.path)
		}
		if info.Deps[i].License != exp.license {
			t.Errorf("dep[%d].License = %q, want %q", i, info.Deps[i].License, exp.license)
		}
	}
}

func TestWriteText(t *testing.T) {
	info := sampleInfo()
	var buf bytes.Buffer
	if err := writeText(info, &buf, false); err != nil {
		t.Fatal(err)
	}

	out := buf.String()

	checks := []string{
		"Go version:",
		"go1.22.0",
		"Module:",
		"github.com/example/myapp",
		"Main:",
		"(Apache-2.0)",
		"PACKAGE",
		"VERSION",
		"LICENSE",
		"github.com/pkg/errors",
		"v0.9.1",
		"BSD-2-Clause",
		"github.com/google/uuid",
		"v1.6.0",
		"BSD-3-Clause",
		"github.com/stretchr/testify",
		"v1.9.0",
		"MIT",
	}

	for _, check := range checks {
		if !strings.Contains(out, check) {
			t.Errorf("text output missing %q", check)
		}
	}

	// Should NOT contain LINK header without links flag
	if strings.Contains(out, "LINK") {
		t.Error("text output should not contain LINK column without links flag")
	}
}

func TestWriteTextWithLinks(t *testing.T) {
	info := sampleInfo()
	var buf bytes.Buffer
	if err := writeText(info, &buf, true); err != nil {
		t.Fatal(err)
	}

	out := buf.String()

	if !strings.Contains(out, "LINK") {
		t.Error("text output with links should contain LINK column")
	}
	if !strings.Contains(out, "https://github.com/google/uuid/blob/v1.6.0/LICENSE") {
		t.Error("text output with links should contain license link")
	}
}

func TestWriteTextWithReplace(t *testing.T) {
	info := sampleInfoWithReplace()
	var buf bytes.Buffer
	if err := writeText(info, &buf, false); err != nil {
		t.Fatal(err)
	}

	out := buf.String()

	if !strings.Contains(out, "github.com/new/pkg") {
		t.Error("text output should show replacement package path")
	}
	if !strings.Contains(out, "replaces github.com/old/pkg@v1.0.0") {
		t.Error("text output should show replaces annotation")
	}
}

func TestWriteCSV(t *testing.T) {
	info := sampleInfo()
	var buf bytes.Buffer
	if err := writeCSV(info, &buf, false); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	lines := strings.Split(strings.TrimSpace(out), "\n")

	if len(lines) < 4 { // header + 3 deps
		t.Fatalf("expected at least 4 lines, got %d", len(lines))
	}

	// Check header
	if lines[0] != "package,version,license" {
		t.Errorf("CSV header = %q, want %q", lines[0], "package,version,license")
	}

	// Check data rows exist
	found := false
	for _, line := range lines[1:] {
		if strings.HasPrefix(line, "github.com/pkg/errors,") {
			found = true
			if !strings.Contains(line, "v0.9.1") || !strings.Contains(line, "BSD-2-Clause") {
				t.Errorf("unexpected CSV row: %s", line)
			}
		}
	}
	if !found {
		t.Error("CSV output missing github.com/pkg/errors row")
	}
}

func TestWriteCSVWithLinks(t *testing.T) {
	info := sampleInfo()
	var buf bytes.Buffer
	if err := writeCSV(info, &buf, true); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	lines := strings.Split(strings.TrimSpace(out), "\n")

	if lines[0] != "package,version,license,link" {
		t.Errorf("CSV header with links = %q, want %q", lines[0], "package,version,license,link")
	}

	found := false
	for _, line := range lines[1:] {
		if strings.Contains(line, "github.com/google/uuid") {
			found = true
			if !strings.Contains(line, "https://github.com/google/uuid/blob/v1.6.0/LICENSE") {
				t.Errorf("CSV with links missing link for uuid: %s", line)
			}
		}
	}
	if !found {
		t.Error("CSV output missing github.com/google/uuid row")
	}
}

func TestWriteCSVWithReplace(t *testing.T) {
	info := sampleInfoWithReplace()
	var buf bytes.Buffer
	if err := writeCSV(info, &buf, false); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	// Replace should show the replacement package
	if !strings.Contains(out, "github.com/new/pkg") {
		t.Error("CSV should show replacement package path")
	}
	// Original path should not appear as package column
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for _, line := range lines[1:] {
		if strings.HasPrefix(line, "github.com/old/pkg,") {
			t.Error("CSV should not show original package path as first column when replaced")
		}
	}
}

func TestWriteYAML(t *testing.T) {
	info := sampleInfo()
	var buf bytes.Buffer
	if err := writeYAML(info, &buf, false); err != nil {
		t.Fatal(err)
	}

	out := buf.String()

	checks := []string{
		"go_version: go1.22.0",
		"module: github.com/example/myapp",
		"main:",
		"  path: github.com/example/myapp",
		"  version: v1.0.0",
		"  license: Apache-2.0",
		"dependencies:",
		"  - package: github.com/pkg/errors",
		"    version: v0.9.1",
		"    license: BSD-2-Clause",
	}

	for _, check := range checks {
		if !strings.Contains(out, check) {
			t.Errorf("YAML output missing %q", check)
		}
	}

	// Should not contain link fields without links flag
	if strings.Contains(out, "    link:") {
		t.Error("YAML output should not contain link fields without links flag")
	}
}

func TestWriteYAMLWithLinks(t *testing.T) {
	info := sampleInfo()
	var buf bytes.Buffer
	if err := writeYAML(info, &buf, true); err != nil {
		t.Fatal(err)
	}

	out := buf.String()

	if !strings.Contains(out, "    link: https://github.com/google/uuid/blob/v1.6.0/LICENSE") {
		t.Error("YAML with links should contain license link for uuid")
	}
}

func TestWriteYAMLWithReplace(t *testing.T) {
	info := sampleInfoWithReplace()
	var buf bytes.Buffer
	if err := writeYAML(info, &buf, false); err != nil {
		t.Fatal(err)
	}

	out := buf.String()

	if !strings.Contains(out, "  - package: github.com/new/pkg") {
		t.Error("YAML should show replacement package")
	}
	if !strings.Contains(out, "    replaces: github.com/old/pkg@v1.0.0") {
		t.Error("YAML should show replaces annotation")
	}
}

func TestWriteYAMLMainNoLicense(t *testing.T) {
	info := sampleInfo()
	info.Main.License = ""
	var buf bytes.Buffer
	if err := writeYAML(info, &buf, false); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	// Should have main: block but no license under it
	lines := strings.Split(out, "\n")
	inMain := false
	for _, line := range lines {
		if line == "main:" {
			inMain = true
			continue
		}
		if inMain && strings.HasPrefix(line, "  license:") {
			t.Error("YAML should not include license under main when empty")
		}
		if inMain && !strings.HasPrefix(line, "  ") {
			inMain = false
		}
	}
}

func TestWriteJSON(t *testing.T) {
	info := sampleInfo()
	var buf bytes.Buffer
	if err := writeJSON(info, &buf, false); err != nil {
		t.Fatal(err)
	}

	var out jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if out.GoVersion != "go1.22.0" {
		t.Errorf("go_version = %q, want %q", out.GoVersion, "go1.22.0")
	}
	if out.Module != "github.com/example/myapp" {
		t.Errorf("module = %q, want %q", out.Module, "github.com/example/myapp")
	}
	if out.Main.Path != "github.com/example/myapp" {
		t.Errorf("main.path = %q, want %q", out.Main.Path, "github.com/example/myapp")
	}
	if out.Main.License != "Apache-2.0" {
		t.Errorf("main.license = %q, want %q", out.Main.License, "Apache-2.0")
	}
	if len(out.Dependencies) != 3 {
		t.Fatalf("expected 3 dependencies, got %d", len(out.Dependencies))
	}
	// No link fields without links flag
	for _, dep := range out.Dependencies {
		if dep.Link != "" {
			t.Errorf("dependency %s should not have link without links flag", dep.Path)
		}
	}
}

func TestWriteJSONWithLinks(t *testing.T) {
	info := sampleInfo()
	var buf bytes.Buffer
	if err := writeJSON(info, &buf, true); err != nil {
		t.Fatal(err)
	}

	var out jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	found := false
	for _, dep := range out.Dependencies {
		if dep.Path == "github.com/google/uuid" {
			found = true
			if dep.Link != "https://github.com/google/uuid/blob/v1.6.0/LICENSE" {
				t.Errorf("uuid link = %q, want license link", dep.Link)
			}
		}
	}
	if !found {
		t.Error("JSON output missing uuid dependency")
	}
}

func TestWriteJSONWithReplace(t *testing.T) {
	info := sampleInfoWithReplace()
	var buf bytes.Buffer
	if err := writeJSON(info, &buf, false); err != nil {
		t.Fatal(err)
	}

	var out jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	found := false
	for _, dep := range out.Dependencies {
		if dep.Path == "github.com/new/pkg" {
			found = true
			if dep.Replace != "github.com/old/pkg@v1.0.0" {
				t.Errorf("replaces = %q, want %q", dep.Replace, "github.com/old/pkg@v1.0.0")
			}
		}
		if dep.Path == "github.com/old/pkg" {
			t.Error("JSON should show replacement, not original")
		}
	}
	if !found {
		t.Error("JSON should contain replacement package github.com/new/pkg")
	}
}

func TestWriteToFile(t *testing.T) {
	info := sampleInfo()
	dir := t.TempDir()

	tests := []struct {
		name  string
		ext   string
		check func(t *testing.T, content string)
	}{
		{
			name: "txt",
			ext:  ".txt",
			check: func(t *testing.T, content string) {
				if !strings.Contains(content, "PACKAGE") {
					t.Error(".txt file should contain PACKAGE header")
				}
			},
		},
		{
			name: "csv",
			ext:  ".csv",
			check: func(t *testing.T, content string) {
				if !strings.HasPrefix(content, "package,") {
					t.Error(".csv file should start with package header")
				}
			},
		},
		{
			name: "yml",
			ext:  ".yml",
			check: func(t *testing.T, content string) {
				if !strings.HasPrefix(content, "go_version:") {
					t.Error(".yml file should start with go_version")
				}
			},
		},
		{
			name: "yaml",
			ext:  ".yaml",
			check: func(t *testing.T, content string) {
				if !strings.HasPrefix(content, "go_version:") {
					t.Error(".yaml file should start with go_version")
				}
			},
		},
		{
			name: "json",
			ext:  ".json",
			check: func(t *testing.T, content string) {
				if !strings.Contains(content, "go_version") {
					t.Error(".json file should contain go_version")
				}
			},
		},
		{
			name: "cyclonedx.json",
			ext:  ".cyclonedx.json",
			check: func(t *testing.T, content string) {
				if !strings.Contains(content, "CycloneDX") {
					t.Error(".cyclonedx.json file should contain CycloneDX bomFormat")
				}
			},
		},
		{
			name: "spdx2.json",
			ext:  ".spdx2.json",
			check: func(t *testing.T, content string) {
				if !strings.Contains(content, "SPDX-2.3") {
					t.Error(".spdx2.json file should contain SPDX-2.3")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, "output"+tt.ext)
			if err := Write(info, path, "", false); err != nil {
				t.Fatal(err)
			}

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, string(data))
		})
	}
}

func TestWriteToFileWithLinks(t *testing.T) {
	info := sampleInfo()
	dir := t.TempDir()

	tests := []struct {
		ext   string
		check func(t *testing.T, content string)
	}{
		{
			ext: ".txt",
			check: func(t *testing.T, content string) {
				if !strings.Contains(content, "LINK") {
					t.Error(".txt with links should have LINK header")
				}
			},
		},
		{
			ext: ".csv",
			check: func(t *testing.T, content string) {
				if !strings.Contains(content, "link") {
					t.Error(".csv with links should have link header")
				}
			},
		},
		{
			ext: ".yml",
			check: func(t *testing.T, content string) {
				if !strings.Contains(content, "link:") {
					t.Error(".yml with links should have link field")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.ext, func(t *testing.T) {
			path := filepath.Join(dir, "output"+tt.ext)
			if err := Write(info, path, "", true); err != nil {
				t.Fatal(err)
			}

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, string(data))
		})
	}
}

func TestWriteUnsupportedFormat(t *testing.T) {
	info := sampleInfo()
	dir := t.TempDir()
	path := filepath.Join(dir, "output.xml")

	err := Write(info, path, "", false)
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported output format") {
		t.Errorf("error = %v, want unsupported output format error", err)
	}
}

func TestWriteStdout(t *testing.T) {
	info := sampleInfo()

	// Write with empty path goes to stdout. We capture by redirecting.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := Write(info, "", "", false)

	_ = w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	out := buf.String()

	if !strings.Contains(out, "PACKAGE") {
		t.Error("stdout output should contain PACKAGE header")
	}
}

func TestWriteNoDeps(t *testing.T) {
	info := &packages.Info{
		GoVersion: "go1.22.0",
		Path:      "github.com/example/empty",
		Main: packages.Package{
			Path:    "github.com/example/empty",
			Version: "v0.0.1",
		},
		Deps: nil,
	}

	var buf bytes.Buffer
	if err := writeText(info, &buf, false); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if !strings.Contains(out, "PACKAGE") {
		t.Error("output should still have header even with no deps")
	}
	// Should only have header lines, no data rows
	lines := strings.Split(strings.TrimSpace(out), "\n")
	// Header: Go version, Module, Main, blank, column header = 5 lines
	if len(lines) != 5 {
		t.Errorf("expected 5 lines for empty deps, got %d:\n%s", len(lines), out)
	}
}

func TestWriteCycloneDX(t *testing.T) {
	info := sampleInfo()
	var buf bytes.Buffer
	if err := writeCycloneDX(info, &buf); err != nil {
		t.Fatal(err)
	}

	var bom cdxBOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want %q", bom.BOMFormat, "CycloneDX")
	}
	if bom.SpecVersion != "1.7" {
		t.Errorf("specVersion = %q, want %q", bom.SpecVersion, "1.7")
	}
	if bom.Metadata.Timestamp == "" {
		t.Error("metadata.timestamp should not be empty")
	}
	if bom.Schema != "https://cyclonedx.org/schema/bom-1.7.schema.json" {
		t.Errorf("$schema = %q", bom.Schema)
	}
	if tools := bom.Metadata.Tools.Components; len(tools) != 1 || tools[0].Name != "github.com/oktalz/go-sbom" || tools[0].Type != "application" {
		t.Errorf("metadata.tools = %v, want [{Name: github.com/oktalz/go-sbom}]", bom.Metadata.Tools)
	}
	if bom.Metadata.Component == nil {
		t.Fatal("metadata.component should not be nil")
	}
	if bom.Metadata.Component.Name != "github.com/example/myapp" {
		t.Errorf("metadata.component.name = %q, want %q", bom.Metadata.Component.Name, "github.com/example/myapp")
	}
	if bom.Metadata.Component.Type != "application" {
		t.Errorf("metadata.component.type = %q, want %q", bom.Metadata.Component.Type, "application")
	}
	if len(bom.Metadata.Component.Licenses) != 1 || bom.Metadata.Component.Licenses[0].License.ID != "Apache-2.0" {
		t.Error("metadata.component should have Apache-2.0 license")
	}

	if len(bom.Components) != 3 {
		t.Fatalf("expected 3 components, got %d", len(bom.Components))
	}
	for _, comp := range bom.Components {
		if comp.Type != "library" {
			t.Errorf("component %s type = %q, want %q", comp.Name, comp.Type, "library")
		}
		if comp.Purl == "" {
			t.Errorf("component %s should have a purl", comp.Name)
		}
	}
}

func TestWriteCycloneDXWithReplace(t *testing.T) {
	info := sampleInfoWithReplace()
	var buf bytes.Buffer
	if err := writeCycloneDX(info, &buf); err != nil {
		t.Fatal(err)
	}

	var bom cdxBOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Should use replacement package info
	found := false
	for _, comp := range bom.Components {
		if comp.Name == "github.com/new/pkg" {
			found = true
			if comp.Version != "v2.0.0" {
				t.Errorf("replaced component version = %q, want %q", comp.Version, "v2.0.0")
			}
		}
		if comp.Name == "github.com/old/pkg" {
			t.Error("CycloneDX should show replacement, not original")
		}
	}
	if !found {
		t.Error("CycloneDX should contain replacement package github.com/new/pkg")
	}
}

func TestWriteCycloneDXNoDeps(t *testing.T) {
	info := &packages.Info{
		GoVersion: "go1.22.0",
		Path:      "github.com/example/empty",
		Main: packages.Package{
			Path:    "github.com/example/empty",
			Version: "v0.0.1",
		},
		Deps: nil,
	}

	var buf bytes.Buffer
	if err := writeCycloneDX(info, &buf); err != nil {
		t.Fatal(err)
	}

	var bom cdxBOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if bom.Components != nil {
		t.Errorf("expected nil components for no deps, got %d", len(bom.Components))
	}
}

func TestWriteCycloneDXUnknownLicenseOmitted(t *testing.T) {
	info := &packages.Info{
		Main: packages.Package{Path: "github.com/example/app", Version: "v1.0.0"},
		Deps: []packages.Package{
			{Path: "github.com/some/pkg", Version: "v1.0.0", License: "Unknown"},
		},
	}

	var buf bytes.Buffer
	if err := writeCycloneDX(info, &buf); err != nil {
		t.Fatal(err)
	}

	var bom cdxBOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(bom.Components) != 1 {
		t.Fatal("expected 1 component")
	}
	if len(bom.Components[0].Licenses) != 0 {
		t.Error("Unknown license should be omitted from CycloneDX output")
	}
}

func TestGoPurl(t *testing.T) {
	tests := []struct {
		path    string
		version string
		want    string
	}{
		{"github.com/google/uuid", "v1.6.0", "pkg:golang/github.com/google/uuid@v1.6.0"},
		{"golang.org/x/net", "v0.21.0", "pkg:golang/golang.org/x/net@v0.21.0"},
		{"", "v1.0.0", ""},
	}
	for _, tt := range tests {
		got := goPurl(tt.path, tt.version)
		if got != tt.want {
			t.Errorf("goPurl(%q, %q) = %q, want %q", tt.path, tt.version, got, tt.want)
		}
	}
}

func TestWriteSPDX(t *testing.T) {
	info := sampleInfo()
	var buf bytes.Buffer
	if err := writeSPDX(info, &buf); err != nil {
		t.Fatal(err)
	}

	var doc spdxDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if doc.SPDXVersion != "SPDX-2.3" {
		t.Errorf("spdxVersion = %q, want %q", doc.SPDXVersion, "SPDX-2.3")
	}
	if doc.DataLicense != "CC0-1.0" {
		t.Errorf("dataLicense = %q, want %q", doc.DataLicense, "CC0-1.0")
	}
	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("SPDXID = %q, want %q", doc.SPDXID, "SPDXRef-DOCUMENT")
	}
	if doc.Name != "github.com/example/myapp" {
		t.Errorf("name = %q, want %q", doc.Name, "github.com/example/myapp")
	}
	if !strings.HasPrefix(doc.DocumentNamespace, "https://spdx.org/spdxdocs/") {
		t.Errorf("documentNamespace should start with https://spdx.org/spdxdocs/, got %q", doc.DocumentNamespace)
	}
	if doc.CreationInfo.Created == "" {
		t.Error("creationInfo.created should not be empty")
	}
	if len(doc.CreationInfo.Creators) != 1 || doc.CreationInfo.Creators[0] != "Tool: github.com/oktalz/go-sbom" {
		t.Errorf("creationInfo.creators = %v, want [Tool: github.com/oktalz/go-sbom]", doc.CreationInfo.Creators)
	}

	// 1 main + 3 deps = 4 packages
	if len(doc.Packages) != 4 {
		t.Fatalf("expected 4 packages, got %d", len(doc.Packages))
	}

	// Main package
	main := doc.Packages[0]
	if main.PrimaryPackagePurpose != "APPLICATION" {
		t.Errorf("main package purpose = %q, want APPLICATION", main.PrimaryPackagePurpose)
	}
	if main.LicenseConcluded != "Apache-2.0" {
		t.Errorf("main licenseConcluded = %q, want Apache-2.0", main.LicenseConcluded)
	}

	// Deps should be LIBRARY
	for _, pkg := range doc.Packages[1:] {
		if pkg.PrimaryPackagePurpose != "LIBRARY" {
			t.Errorf("dep %s purpose = %q, want LIBRARY", pkg.Name, pkg.PrimaryPackagePurpose)
		}
		if len(pkg.ExternalRefs) != 1 {
			t.Errorf("dep %s should have 1 external ref, got %d", pkg.Name, len(pkg.ExternalRefs))
		}
	}

	// Relationships: 1 DESCRIBES + 3 DEPENDS_ON
	if len(doc.Relationships) != 4 {
		t.Fatalf("expected 4 relationships, got %d", len(doc.Relationships))
	}
	if doc.Relationships[0].RelationshipType != "DESCRIBES" {
		t.Errorf("first relationship type = %q, want DESCRIBES", doc.Relationships[0].RelationshipType)
	}
	for _, rel := range doc.Relationships[1:] {
		if rel.RelationshipType != "DEPENDS_ON" {
			t.Errorf("dep relationship type = %q, want DEPENDS_ON", rel.RelationshipType)
		}
	}
}

func TestWriteSPDXDeterministicNamespace(t *testing.T) {
	info := sampleInfo()

	var buf1, buf2 bytes.Buffer
	if err := writeSPDX(info, &buf1); err != nil {
		t.Fatal(err)
	}
	if err := writeSPDX(info, &buf2); err != nil {
		t.Fatal(err)
	}

	var doc1, doc2 spdxDocument
	if err := json.Unmarshal(buf1.Bytes(), &doc1); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(buf2.Bytes(), &doc2); err != nil {
		t.Fatal(err)
	}

	if doc1.DocumentNamespace != doc2.DocumentNamespace {
		t.Errorf("SPDX document namespace should be deterministic:\n  first:  %s\n  second: %s",
			doc1.DocumentNamespace, doc2.DocumentNamespace)
	}
}

func TestWriteSPDXWithReplace(t *testing.T) {
	info := sampleInfoWithReplace()
	var buf bytes.Buffer
	if err := writeSPDX(info, &buf); err != nil {
		t.Fatal(err)
	}

	var doc spdxDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	found := false
	for _, pkg := range doc.Packages {
		if pkg.Name == "github.com/new/pkg" {
			found = true
			if pkg.VersionInfo != "v2.0.0" {
				t.Errorf("replaced package version = %q, want v2.0.0", pkg.VersionInfo)
			}
			if pkg.LicenseConcluded != "Apache-2.0" {
				t.Errorf("replaced package license = %q, want Apache-2.0", pkg.LicenseConcluded)
			}
		}
		if pkg.Name == "github.com/old/pkg" {
			t.Error("SPDX should show replacement, not original")
		}
	}
	if !found {
		t.Error("SPDX should contain replacement package github.com/new/pkg")
	}
}

func TestWriteSPDXNoDeps(t *testing.T) {
	info := &packages.Info{
		GoVersion: "go1.22.0",
		Path:      "github.com/example/empty",
		Main: packages.Package{
			Path:    "github.com/example/empty",
			Version: "v0.0.1",
		},
		Deps: nil,
	}

	var buf bytes.Buffer
	if err := writeSPDX(info, &buf); err != nil {
		t.Fatal(err)
	}

	var doc spdxDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Only main package
	if len(doc.Packages) != 1 {
		t.Errorf("expected 1 package for no deps, got %d", len(doc.Packages))
	}
	// Only DESCRIBES relationship
	if len(doc.Relationships) != 1 {
		t.Errorf("expected 1 relationship for no deps, got %d", len(doc.Relationships))
	}
	if doc.Relationships[0].RelationshipType != "DESCRIBES" {
		t.Errorf("relationship type = %q, want DESCRIBES", doc.Relationships[0].RelationshipType)
	}
}

func TestWriteSPDXUnknownLicense(t *testing.T) {
	info := &packages.Info{
		Main: packages.Package{Path: "github.com/example/app", Version: "v1.0.0"},
		Deps: []packages.Package{
			{Path: "github.com/some/pkg", Version: "v1.0.0", License: "Unknown"},
			{Path: "github.com/other/pkg", Version: "v2.0.0"},
		},
	}

	var buf bytes.Buffer
	if err := writeSPDX(info, &buf); err != nil {
		t.Fatal(err)
	}

	var doc spdxDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	for _, pkg := range doc.Packages[1:] {
		if pkg.LicenseConcluded != "NOASSERTION" {
			t.Errorf("package %s licenseConcluded = %q, want NOASSERTION", pkg.Name, pkg.LicenseConcluded)
		}
		if pkg.LicenseDeclared != "NOASSERTION" {
			t.Errorf("package %s licenseDeclared = %q, want NOASSERTION", pkg.Name, pkg.LicenseDeclared)
		}
	}
}

func TestSpdxID(t *testing.T) {
	tests := []struct {
		path    string
		version string
		want    string
	}{
		{"github.com/google/uuid", "v1.6.0", "SPDXRef-github.com-google-uuid-v1.6.0"},
		{"golang.org/x/net", "v0.21.0", "SPDXRef-golang.org-x-net-v0.21.0"},
		{"github.com/example/app", "", "SPDXRef-github.com-example-app"},
	}
	for _, tt := range tests {
		got := spdxID(tt.path, tt.version)
		if got != tt.want {
			t.Errorf("spdxID(%q, %q) = %q, want %q", tt.path, tt.version, got, tt.want)
		}
	}
}

func TestWriteWithFormatOverride(t *testing.T) {
	info := sampleInfo()

	tests := []struct {
		format string
		check  func(t *testing.T, content string)
	}{
		{
			format: "text",
			check: func(t *testing.T, content string) {
				if !strings.Contains(content, "PACKAGE") {
					t.Error("text format should contain PACKAGE header")
				}
			},
		},
		{
			format: "csv",
			check: func(t *testing.T, content string) {
				if !strings.HasPrefix(content, "package,") {
					t.Error("csv format should start with package header")
				}
			},
		},
		{
			format: "yaml",
			check: func(t *testing.T, content string) {
				if !strings.HasPrefix(content, "go_version:") {
					t.Error("yaml format should start with go_version")
				}
			},
		},
		{
			format: "json",
			check: func(t *testing.T, content string) {
				if !strings.Contains(content, "go_version") {
					t.Error("json format should contain go_version")
				}
			},
		},
		{
			format: "cyclonedx",
			check: func(t *testing.T, content string) {
				if !strings.Contains(content, "CycloneDX") {
					t.Error("cyclonedx format should contain CycloneDX")
				}
			},
		},
		{
			format: "spdx2",
			check: func(t *testing.T, content string) {
				if !strings.Contains(content, "SPDX-2.3") {
					t.Error("spdx format should contain SPDX-2.3")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "output.dat")
			if err := Write(info, path, tt.format, false); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, string(data))
		})
	}
}

func TestWriteFormatOverrideToStdout(t *testing.T) {
	info := sampleInfo()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := Write(info, "", "csv", false)

	_ = w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	out := buf.String()

	if !strings.HasPrefix(out, "package,") {
		t.Error("csv format to stdout should start with package header")
	}
}

func TestDeterministicUUID(t *testing.T) {
	info := sampleInfo()
	uuid1 := deterministicUUID(info)
	uuid2 := deterministicUUID(info)
	if uuid1 != uuid2 {
		t.Errorf("deterministicUUID should be stable: %q != %q", uuid1, uuid2)
	}

	// Different info should produce different UUID
	info2 := sampleInfo()
	info2.Deps = append(info2.Deps, packages.Package{
		Path: "github.com/extra/pkg", Version: "v1.0.0", License: "MIT",
	})
	uuid3 := deterministicUUID(info2)
	if uuid1 == uuid3 {
		t.Error("deterministicUUID should differ for different dependency sets")
	}
}
