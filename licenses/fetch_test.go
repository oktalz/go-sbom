package licenses

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oktalz/go-sbom/packages"
)

const testMITText = `MIT License

Copyright (c) 2024 Example

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`

func fastRetries(t *testing.T) {
	t.Helper()
	orig := retryBackoff
	retryBackoff = time.Millisecond
	t.Cleanup(func() { retryBackoff = orig })
}

// isolateGoEnv points module fetching at the given proxy and an empty module
// cache, so tests never touch the network or the real cache.
func isolateGoEnv(t *testing.T, goproxy string) string {
	t.Helper()
	cache := t.TempDir()
	t.Setenv("GOPROXY", goproxy)
	t.Setenv("GOMODCACHE", cache)
	t.Setenv("GOPRIVATE", "")
	t.Setenv("GONOPROXY", "")
	t.Setenv("GOFLAGS", "")
	return cache
}

func TestParseProxyList(t *testing.T) {
	tests := []struct {
		in   string
		want []proxyEntry
	}{
		{"https://a", []proxyEntry{{URL: "https://a"}}},
		{"https://a,https://b,direct", []proxyEntry{{URL: "https://a"}, {URL: "https://b"}, {URL: "direct"}}},
		{"https://a|https://b,direct", []proxyEntry{{URL: "https://a", FallbackOnAnyError: true}, {URL: "https://b"}, {URL: "direct"}}},
		{"https://a,off,https://b", []proxyEntry{{URL: "https://a"}}},
		{"off", nil},
		{" https://a , ,https://b ", []proxyEntry{{URL: "https://a"}, {URL: "https://b"}}},
	}
	for _, tt := range tests {
		got := parseProxyList(tt.in)
		if len(got) != len(tt.want) {
			t.Errorf("parseProxyList(%q) = %v, want %v", tt.in, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("parseProxyList(%q)[%d] = %v, want %v", tt.in, i, got[i], tt.want[i])
			}
		}
	}
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{&statusError{Code: 404}, false},
		{&statusError{Code: 410}, false},
		{&statusError{Code: 403}, false},
		{&statusError{Code: 429}, true},
		{&statusError{Code: 502}, true},
		{errors.New("connection reset"), true},
		{context.DeadlineExceeded, false},
		{errZipTooLarge, false},
	}
	for _, tt := range tests {
		if got := isRetryable(tt.err); got != tt.want {
			t.Errorf("isRetryable(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

func zipHandler(t *testing.T, modulePath, version string) http.HandlerFunc {
	t.Helper()
	data := createTestZip(t, map[string]string{modulePath + "@" + version + "/LICENSE": testMITText})
	return func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(data)
	}
}

func TestDownloadNotFoundIsNotRetriedAndFallsBack(t *testing.T) {
	fastRetries(t)
	var first, second atomic.Int32
	s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		first.Add(1)
		http.NotFound(w, nil)
	}))
	defer s1.Close()
	ok := zipHandler(t, "example.com/mod", "v1.0.0")
	s2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		second.Add(1)
		ok(w, r)
	}))
	defer s2.Close()

	path, err := downloadModuleZip(t.Context(), parseProxyList(s1.URL+","+s2.URL), "example.com/mod", "v1.0.0", Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	if first.Load() != 1 {
		t.Errorf("404 proxy got %d requests, want 1 (no retries)", first.Load())
	}
	if second.Load() != 1 {
		t.Errorf("second proxy got %d requests, want 1", second.Load())
	}
}

func TestDownloadServerErrorRetriedNoCommaFallback(t *testing.T) {
	fastRetries(t)
	var first, second atomic.Int32
	s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		first.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer s1.Close()
	s2 := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		second.Add(1)
	}))
	defer s2.Close()

	_, err := downloadModuleZip(t.Context(), parseProxyList(s1.URL+","+s2.URL), "example.com/mod", "v1.0.0", Options{})
	if err == nil {
		t.Fatal("expected error")
	}
	if first.Load() != maxRetries {
		t.Errorf("5xx proxy got %d requests, want %d", first.Load(), maxRetries)
	}
	if second.Load() != 0 {
		t.Errorf("',' must not fall back after a 5xx, but second proxy got %d requests", second.Load())
	}
}

func TestDownloadPipeFallsBackOnAnyError(t *testing.T) {
	fastRetries(t)
	s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer s1.Close()
	s2 := httptest.NewServer(zipHandler(t, "example.com/mod", "v1.0.0"))
	defer s2.Close()

	path, err := downloadModuleZip(t.Context(), parseProxyList(s1.URL+"|"+s2.URL), "example.com/mod", "v1.0.0", Options{})
	if err != nil {
		t.Fatalf("'|' should fall back after a 403: %v", err)
	}
	_ = os.Remove(path)
}

func TestDownloadEscapesPathAndVersion(t *testing.T) {
	var gotPath string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		http.NotFound(w, r)
	}))
	defer s.Close()

	_, _ = downloadModuleZip(t.Context(), parseProxyList(s.URL), "github.com/BurntSushi/toml", "v1.0.0-RC1", Options{})
	if want := "/github.com/!burnt!sushi/toml/@v/v1.0.0-!r!c1.zip"; gotPath != want {
		t.Errorf("requested %q, want %q", gotPath, want)
	}
}

func TestFetchFromProxy(t *testing.T) {
	s := httptest.NewServer(zipHandler(t, "example.com/mod", "v1.0.0"))
	defer s.Close()
	isolateGoEnv(t, s.URL)

	info := &packages.Info{Deps: []packages.Package{{Path: "example.com/mod", Version: "v1.0.0"}}}
	if err := Fetch(t.Context(), info, Options{}); err != nil {
		t.Fatal(err)
	}
	if got := info.Deps[0].License; got != "MIT" {
		t.Errorf("License = %q, want MIT", got)
	}
}

func failingProxy(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected proxy request: %s", r.URL.Path)
		http.NotFound(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func TestFetchSkipsPackagesWithLicense(t *testing.T) {
	isolateGoEnv(t, failingProxy(t).URL)

	info := &packages.Info{Deps: []packages.Package{
		{Path: "company.com/a", Version: "v1.0.0", License: "Proprietary"},
		{Path: "company.com/old", Version: "v1.0.0", Replace: &packages.Package{Path: "company.com/new", Version: "v1.0.0", License: "MIT"}},
	}}
	if err := Fetch(t.Context(), info, Options{}); err != nil {
		t.Fatal(err)
	}
	if info.Deps[0].License != "Proprietary" || info.Deps[1].Replace.License != "MIT" {
		t.Errorf("preset licenses changed: %+v", info.Deps)
	}
}

func TestFetchPrivateModuleNotSentToProxy(t *testing.T) {
	isolateGoEnv(t, failingProxy(t).URL)
	t.Setenv("GOPRIVATE", "company.com/*")

	info := &packages.Info{Deps: []packages.Package{{Path: "company.com/secret/pkg", Version: "v1.2.3"}}}
	if err := Fetch(t.Context(), info, Options{}); err != nil {
		t.Fatal(err)
	}
	if got := info.Deps[0].License; got != "Unknown" {
		t.Errorf("License = %q, want Unknown", got)
	}
}

func TestFetchUsesModuleCache(t *testing.T) {
	cache := isolateGoEnv(t, failingProxy(t).URL)
	t.Setenv("GOPRIVATE", "company.com") // private, but cached: still resolved

	dir := filepath.Join(cache, "company.com", "!my!lib@v1.0.0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "LICENSE"), []byte(testMITText), 0o644); err != nil {
		t.Fatal(err)
	}

	info := &packages.Info{Deps: []packages.Package{{Path: "company.com/MyLib", Version: "v1.0.0"}}}
	if err := Fetch(t.Context(), info, Options{}); err != nil {
		t.Fatal(err)
	}
	if got := info.Deps[0].License; got != "MIT" {
		t.Errorf("License = %q, want MIT", got)
	}
	if want := "https://pkg.go.dev/company.com/MyLib@v1.0.0?tab=licenses"; info.Deps[0].LicenseLink != want {
		t.Errorf("LicenseLink = %q, want %q", info.Deps[0].LicenseLink, want)
	}
}

func TestFetchLocalReplace(t *testing.T) {
	isolateGoEnv(t, failingProxy(t).URL)

	project := t.TempDir()
	fork := filepath.Join(project, "fork")
	if err := os.MkdirAll(fork, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fork, "license.md"), []byte(testMITText), 0o644); err != nil {
		t.Fatal(err)
	}

	info := &packages.Info{
		Dir:  project,
		Deps: []packages.Package{{Path: "example.com/orig", Version: "v1.0.0", Replace: &packages.Package{Path: "./fork"}}},
	}
	if err := Fetch(t.Context(), info, Options{}); err != nil {
		t.Fatal(err)
	}
	if got := info.Deps[0].Replace.License; got != "MIT" {
		t.Errorf("Replace.License = %q, want MIT", got)
	}
}

func TestFindLicenseFilePriorityAndCase(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"COPYING", "license.md", "LICENSE-MIT", "README.md"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Run several times: the result must not depend on iteration order.
	for range 5 {
		if got := findLicenseFile(dir); got != "license.md" {
			t.Fatalf("findLicenseFile = %q, want license.md", got)
		}
	}
}

func TestExtractLicenseFromZipPrefersLicenseOverCopying(t *testing.T) {
	zipData := createTestZip(t, map[string]string{
		"m@v1/COPYING":     "copying",
		"m@v1/License.txt": "license",
	})
	content, name, err := extractLicenseFromZip(strings.NewReader(string(zipData)), int64(len(zipData)), "m", "v1")
	if err != nil {
		t.Fatal(err)
	}
	if name != "License.txt" || string(content) != "license" {
		t.Errorf("got %q (%q), want License.txt", name, content)
	}
}
