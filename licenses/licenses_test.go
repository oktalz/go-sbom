package licenses

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	licenseclassifier "github.com/google/licenseclassifier/v2"
	"github.com/google/licenseclassifier/v2/assets"
	"github.com/oktalz/go-sbom/packages"
)

func TestLicenseCandidates(t *testing.T) {
	tests := []struct {
		name  string
		files []string
		want  []string
	}{
		{"well-known name", []string{"main.go", "LICENSE", "README.md"}, []string{"LICENSE"}},
		{"all well-known names, best first", []string{"COPYING", "license.md", "LICENSE-MIT"}, []string{"license.md", "COPYING", "LICENSE-MIT"}},
		{"Rust-style dual license", []string{"LICENSE-APACHE", "LICENSE-MIT", "Cargo.toml"}, []string{"LICENSE-MIT", "LICENSE-APACHE"}},
		{"well-known names, then other names", []string{"LICENSE.libyaml", "LICENSE", "LICENSE-THIRD-PARTY"}, []string{"LICENSE", "LICENSE-THIRD-PARTY", "LICENSE.libyaml"}},
		{"logo license skipped", []string{"LICENSE", "LICENSE-LOGO"}, []string{"LICENSE"}},
		{"other names, all of them", []string{"LICENSE.docs", "LICENSE.code", "LICENSE.apache"}, []string{"LICENSE.apache", "LICENSE.code"}},
		{"other name with SPDX id", []string{"LICENSE-APACHE-2.0.txt", "go.mod"}, []string{"LICENSE-APACHE-2.0.txt"}},
		{"licence and copying prefixes", []string{"Licence-GPL", "COPYING.LIB"}, []string{"COPYING.LIB", "Licence-GPL"}},
		{"REUSE directory", []string{"go.mod", "LICENSES/MIT.txt", "LICENSES/Apache-2.0.txt", "LICENSES/README.md"}, []string{"LICENSES/Apache-2.0.txt", "LICENSES/MIT.txt"}},
		{"top-level file beats REUSE", []string{"LICENSE", "LICENSES/MIT.txt"}, []string{"LICENSE"}},
		{"nested license ignored", []string{"subdir/LICENSE", "main.go"}, nil},
		{"no license", []string{"main.go", "README.md", "licenses.go.txt/x"}, nil},
		// github.com/go-openapi/spec has license.go: source, not a license text
		{"source files named license", []string{"license.go", "license_test.go", "licenses.json"}, nil},
		{"source file next to a license", []string{"license.go", "LICENSE.code"}, []string{"LICENSE.code"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := licenseCandidates(tt.files); !slices.Equal(got, tt.want) {
				t.Errorf("licenseCandidates(%q) = %q, want %q", tt.files, got, tt.want)
			}
		})
	}
}

func TestBuildLicenseLink(t *testing.T) {
	tests := []struct {
		name       string
		modulePath string
		version    string
		file       string
		expect     string
	}{
		{
			name:       "github module",
			modulePath: "github.com/google/uuid",
			version:    "v1.6.0",
			file:       "LICENSE",
			expect:     "https://github.com/google/uuid/blob/v1.6.0/LICENSE",
		},
		{
			name:       "gitlab module",
			modulePath: "gitlab.com/org/repo",
			version:    "v1.0.0",
			file:       "LICENSE",
			expect:     "https://gitlab.com/org/repo/-/blob/v1.0.0/LICENSE",
		},
		{
			name:       "gitea module",
			modulePath: "gitea.com/org/repo",
			version:    "v1.0.0",
			file:       "LICENSE",
			expect:     "https://gitea.com/org/repo/src/tag/v1.0.0/LICENSE",
		},
		{
			name:       "codeberg module",
			modulePath: "codeberg.org/org/repo",
			version:    "v1.0.0",
			file:       "LICENSE",
			expect:     "https://codeberg.org/org/repo/src/tag/v1.0.0/LICENSE",
		},
		{
			name:       "non-github module",
			modulePath: "golang.org/x/net",
			version:    "v0.21.0",
			file:       "LICENSE",
			expect:     "https://pkg.go.dev/golang.org/x/net@v0.21.0?tab=licenses",
		},
		{
			name:       "empty file",
			modulePath: "github.com/google/uuid",
			version:    "v1.6.0",
			file:       "",
			expect:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildLicenseLink(tt.modulePath, tt.version, tt.file)
			if got != tt.expect {
				t.Errorf("buildLicenseLink(%q, %q, %q) = %q, want %q",
					tt.modulePath, tt.version, tt.file, got, tt.expect)
			}
		})
	}
}

func TestProxyURLs(t *testing.T) {
	// Save and restore env
	orig := os.Getenv("GOPROXY")
	defer os.Setenv("GOPROXY", orig)

	tests := []struct {
		name    string
		env     string
		minURLs int
	}{
		{
			name:    "custom proxy",
			env:     "https://myproxy.example.com",
			minURLs: 1,
		},
		{
			name:    "multiple proxies",
			env:     "https://proxy1.example.com,https://proxy2.example.com,direct",
			minURLs: 2,
		},
		{
			name:    "with direct",
			env:     "https://proxy.golang.org,direct",
			minURLs: 1, // "direct" is included in the list
		},
		{
			name:    "off stops parsing",
			env:     "https://proxy1.example.com,off,https://proxy2.example.com",
			minURLs: 1, // only first proxy before "off"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("GOPROXY", tt.env)
			urls := proxyURLs()
			if len(urls) < tt.minURLs {
				t.Errorf("proxyURLs() returned %d URLs, want at least %d: %v", len(urls), tt.minURLs, urls)
			}
		})
	}
}

func TestProxyURLsDefault(t *testing.T) {
	orig := os.Getenv("GOPROXY")
	defer os.Setenv("GOPROXY", orig)

	_ = os.Setenv("GOPROXY", "")
	urls := proxyURLs()
	// Should fall back to go env or default
	if len(urls) == 0 {
		t.Error("proxyURLs() with empty GOPROXY should return at least one URL")
	}
}

func createTestZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	for name, content := range files {
		fw, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestZipLicenseFiles(t *testing.T) {
	modulePath := "github.com/example/pkg"
	version := "v1.0.0"
	prefix := modulePath + "@" + version + "/"

	zipData := createTestZip(t, map[string]string{
		prefix + "main.go":   "package main",
		prefix + "LICENSE":   "MIT License\n\nPermission is hereby granted...",
		prefix + "README.md": "# Example",
	})

	files, err := zipLicenseFiles(bytes.NewReader(zipData), int64(len(zipData)), modulePath, version)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d license files, want 1", len(files))
	}
	if files[0].Name != "LICENSE" {
		t.Errorf("fileName = %q, want %q", files[0].Name, "LICENSE")
	}
	if !bytes.Contains(files[0].Content, []byte("MIT License")) {
		t.Error("license content should contain 'MIT License'")
	}
}

func TestZipLicenseFilesNoLicense(t *testing.T) {
	modulePath := "github.com/example/pkg"
	version := "v1.0.0"
	prefix := modulePath + "@" + version + "/"

	zipData := createTestZip(t, map[string]string{
		prefix + "main.go":   "package main",
		prefix + "README.md": "# No license here",
	})

	files, err := zipLicenseFiles(bytes.NewReader(zipData), int64(len(zipData)), modulePath, version)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Errorf("expected no license files, got %d", len(files))
	}
}

func TestZipLicenseFilesNestedLicense(t *testing.T) {
	modulePath := "github.com/example/pkg"
	version := "v1.0.0"
	prefix := modulePath + "@" + version + "/"

	// Nested license should NOT be found
	zipData := createTestZip(t, map[string]string{
		prefix + "main.go":        "package main",
		prefix + "subpkg/LICENSE": "Some license",
	})

	files, err := zipLicenseFiles(bytes.NewReader(zipData), int64(len(zipData)), modulePath, version)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Error("nested LICENSE should not be extracted")
	}
}

func TestZipLicenseFilesInvalidData(t *testing.T) {
	_, err := zipLicenseFiles(strings.NewReader("not a zip"), int64(len("not a zip")), "mod", "v1")
	if err == nil {
		t.Fatal("expected error for invalid zip data")
	}
}

// readFixture returns the content of testdata/name.
func readFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func getClassifier(t *testing.T) *licenseclassifier.Classifier {
	t.Helper()
	c, err := assets.DefaultClassifier()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestClassifyLicenseMIT(t *testing.T) {
	classifier := getClassifier(t)

	mitText := readFixture(t, "mit.txt")

	result := classifyLicense(classifier, []byte(mitText), Options{})
	if result != "MIT" {
		t.Errorf("classifyLicense(MIT) = %q, want %q", result, "MIT")
	}
}

func TestClassifyLicenseApache(t *testing.T) {
	classifier := getClassifier(t)

	apacheText := readFixture(t, "apache-2.0.txt")

	result := classifyLicense(classifier, []byte(apacheText), Options{})
	if result != "Apache-2.0" {
		t.Errorf("classifyLicense(Apache) = %q, want %q", result, "Apache-2.0")
	}
}

func TestClassifyLicenseMultiple(t *testing.T) {
	classifier := getClassifier(t)

	// One LICENSE file with two licenses (like gopkg.in/yaml.v3): both are
	// reported, joined with AND, alphabetically without an order.
	text := []byte(readFixture(t, "mit-and-apache-2.0.txt"))
	if got := classifyLicense(classifier, text, Options{}); got != "Apache-2.0 AND MIT" {
		t.Errorf("classifyLicense(MIT + Apache) = %q, want %q", got, "Apache-2.0 AND MIT")
	}
	// With an order (the allowed list), in that order.
	if got := classifyLicense(classifier, text, Options{Order: []string{"mit", "Apache-2.0"}}); got != "MIT AND Apache-2.0" {
		t.Errorf("classifyLicense(MIT + Apache, order MIT first) = %q, want %q", got, "MIT AND Apache-2.0")
	}

	// The same license found twice is reported once.
	twice := []byte(readFixture(t, "mit.txt") + "\n\n" + readFixture(t, "mit.txt"))
	if got := classifyLicense(classifier, twice, Options{}); got != "MIT" {
		t.Errorf("classifyLicense(MIT twice) = %q, want %q", got, "MIT")
	}
}

func TestClassifyLicenseUnknown(t *testing.T) {
	classifier := getClassifier(t)

	result := classifyLicense(classifier, []byte("This is not a license text at all."), Options{})
	if result != "Unknown" {
		t.Errorf("classifyLicense(garbage) = %q, want %q", result, "Unknown")
	}
}

func TestClassifyLicenseEmpty(t *testing.T) {
	classifier := getClassifier(t)

	result := classifyLicense(classifier, []byte(""), Options{})
	if result != "Unknown" {
		t.Errorf("classifyLicense(empty) = %q, want %q", result, "Unknown")
	}
}

func TestClassifyLicenseMinConfidence(t *testing.T) {
	classifier := getClassifier(t)

	mitText := readFixture(t, "mit.txt")

	// With very high threshold, should reject even a perfect match
	result := classifyLicense(classifier, []byte(mitText), Options{MinConfidence: 1.01})
	if result != "Unknown" {
		t.Errorf("classifyLicense with impossible threshold = %q, want %q", result, "Unknown")
	}

	// With zero threshold (default), should classify normally
	result = classifyLicense(classifier, []byte(mitText), Options{MinConfidence: 0})
	if result != "MIT" {
		t.Errorf("classifyLicense with zero threshold = %q, want %q", result, "MIT")
	}
}

func TestDetectLocalLicense(t *testing.T) {
	classifier := getClassifier(t)
	dir := t.TempDir()

	mitText := readFixture(t, "mit.txt")

	if err := os.WriteFile(filepath.Join(dir, "LICENSE"), []byte(mitText), 0o644); err != nil {
		t.Fatal(err)
	}

	result := detectLocalLicense(classifier, dir, Options{})
	if result != "MIT" {
		t.Errorf("detectLocalLicense = %q, want %q", result, "MIT")
	}
}

func TestDetectLocalLicenseNoFile(t *testing.T) {
	classifier := getClassifier(t)
	dir := t.TempDir()

	result := detectLocalLicense(classifier, dir, Options{})
	if result != "" {
		t.Errorf("detectLocalLicense(no file) = %q, want empty", result)
	}
}

func TestDetectLocalLicenseAlternateNames(t *testing.T) {
	classifier := getClassifier(t)

	mitText := readFixture(t, "mit.txt")

	names := []string{"LICENCE", "LICENSE.md", "LICENSE.txt", "COPYING", "MIT-LICENSE"}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, name), []byte(mitText), 0o644); err != nil {
				t.Fatal(err)
			}

			result := detectLocalLicense(classifier, dir, Options{})
			if result == "" {
				t.Errorf("detectLocalLicense with %s returned empty", name)
			}
		})
	}
}

func TestFetchSetsLocalLicense(t *testing.T) {
	dir := t.TempDir()

	mitText := readFixture(t, "mit.txt")

	if err := os.WriteFile(filepath.Join(dir, "LICENSE"), []byte(mitText), 0o644); err != nil {
		t.Fatal(err)
	}

	info := &packages.Info{
		Dir: dir,
		Main: packages.Package{
			Path: "github.com/example/testmod",
		},
		Deps: nil, // no deps to avoid network calls
	}

	ctx := t.Context()
	if err := Fetch(ctx, info, Options{}); err != nil {
		t.Fatal(err)
	}

	if info.Main.License != "MIT" {
		t.Errorf("Main.License = %q, want %q", info.Main.License, "MIT")
	}
}

func TestFetchNoDirSkipsLocalLicense(t *testing.T) {
	info := &packages.Info{
		Dir: "", // no dir
		Main: packages.Package{
			Path: "github.com/example/testmod",
		},
		Deps: nil,
	}

	ctx := t.Context()
	if err := Fetch(ctx, info, Options{}); err != nil {
		t.Fatal(err)
	}

	if info.Main.License != "" {
		t.Errorf("Main.License should be empty when Dir is empty, got %q", info.Main.License)
	}
}

func TestLicenseFileNamesMap(t *testing.T) {
	expected := []string{
		"LICENSE", "LICENSE.md", "LICENSE.txt", "LICENSE.markdown",
		"LICENCE", "LICENCE.md", "LICENCE.txt",
		"COPYING", "COPYING.md", "COPYING.txt",
		"LICENSE-MIT", "LICENSE-APACHE", "LICENSE-2.0.txt",
		"MIT-LICENSE", "LICENSE.MIT", "LICENSE.rst", "UNLICENSE",
	}

	for _, name := range expected {
		if licenseNamePriority(name) < 0 {
			t.Errorf("licenseFileNames missing %q", name)
		}
	}
}

// captureStderr returns what fn writes to os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = orig }()
	fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestVerboseLinesNameTheModule(t *testing.T) {
	classifier := getClassifier(t)
	text := []byte(readFixture(t, "mit-and-apache-2.0.txt"))
	opts := Options{Verbose: true}.forModule("gopkg.in/yaml.v3@v3.0.1")

	out := captureStderr(t, func() { classifyLicense(classifier, text, opts) })

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 3 { // two matches + the result
		t.Fatalf("expected verbose output, got %q", out)
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "verbose: gopkg.in/yaml.v3@v3.0.1: ") {
			t.Errorf("verbose line without module: %q", line)
		}
	}
}

func TestSortLicenses(t *testing.T) {
	tests := []struct {
		names, order, want []string
	}{
		{[]string{"MIT", "BSD-3-Clause", "Apache-2.0"}, nil, []string{"Apache-2.0", "BSD-3-Clause", "MIT"}},
		{[]string{"MIT", "BSD-3-Clause", "Apache-2.0"}, []string{"MIT", "Apache-2.0", "BSD-3-Clause"}, []string{"MIT", "Apache-2.0", "BSD-3-Clause"}},
		// not in the order: last, alphabetically
		{[]string{"MPL-2.0", "BSD-3-Clause", "GPL-2.0", "MIT"}, []string{"MIT", "BSD-3-Clause"}, []string{"MIT", "BSD-3-Clause", "GPL-2.0", "MPL-2.0"}},
		// order entries match case-insensitively
		{[]string{"Apache-2.0", "MIT"}, []string{"mit", "apache-2.0"}, []string{"MIT", "Apache-2.0"}},
	}
	for _, tt := range tests {
		got := slices.Clone(tt.names)
		sortLicenses(got, tt.order)
		if !slices.Equal(got, tt.want) {
			t.Errorf("sortLicenses(%v, %v) = %v, want %v", tt.names, tt.order, got, tt.want)
		}
	}
}
