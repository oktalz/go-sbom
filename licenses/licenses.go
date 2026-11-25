package licenses

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	licenseclassifier "github.com/google/licenseclassifier/v2"
	"github.com/google/licenseclassifier/v2/assets"
	"golang.org/x/mod/module"

	"github.com/oktalz/go-sbom/packages"
)

const (
	defaultProxy   = "https://proxy.golang.org,direct"
	maxConcurrency = 10
	maxRetries     = 3
	depTimeout     = 30 * time.Second
	// maxLicenseFileSize caps how much of a single license file is read.
	maxLicenseFileSize = 1 << 20
	// maxZipFile is the largest module zip the go command accepts
	// (golang.org/x/mod/zip.MaxZipFile).
	maxZipFile = 500 << 20
)

// retryBackoff is the base delay between retries (doubled on each attempt).
var retryBackoff = time.Second

// Options configures the license detection behavior.
type Options struct {
	MinConfidence float64
	Verbose       bool
}

func logVerbose(opts Options, format string, args ...any) {
	if opts.Verbose {
		fmt.Fprintf(os.Stderr, "verbose: "+format+"\n", args...)
	}
}

// proxyEntry is one element of GOPROXY.
type proxyEntry struct {
	URL string
	// FallbackOnAnyError is true when the entry is followed by '|', meaning the
	// next proxy is tried after any error, not only after 404/410.
	FallbackOnAnyError bool
}

// goEnv holds the Go environment settings that affect module fetching.
type goEnv struct {
	// NoProxy lists module path patterns (GONOPROXY, defaulting to GOPRIVATE)
	// that must never be requested from a proxy.
	NoProxy  string
	ModCache string
	Proxies  []proxyEntry
}

// loadGoEnv reads GOPROXY, GONOPROXY, GOPRIVATE and GOMODCACHE once.
// It asks the go command (which honors environment variables and the go.env
// config) and falls back to plain environment variables when go is missing.
func loadGoEnv() goEnv {
	vals := map[string]string{}
	if out, err := exec.Command("go", "env", "-json", "GOPROXY", "GONOPROXY", "GOPRIVATE", "GOMODCACHE").Output(); err == nil {
		_ = json.Unmarshal(out, &vals)
	}
	get := func(key string) string {
		if v, ok := vals[key]; ok {
			return v
		}
		return os.Getenv(key)
	}

	goproxy := get("GOPROXY")
	if goproxy == "" {
		goproxy = defaultProxy
	}
	noProxy := get("GONOPROXY")
	if noProxy == "" {
		noProxy = get("GOPRIVATE")
	}
	modCache := get("GOMODCACHE")
	if modCache == "" {
		gopath := os.Getenv("GOPATH")
		if gopath == "" {
			if home, err := os.UserHomeDir(); err == nil {
				gopath = filepath.Join(home, "go")
			}
		}
		if gopath != "" {
			// GOPATH may be a list; the module cache lives in the first entry.
			modCache = filepath.Join(filepath.SplitList(gopath)[0], "pkg", "mod")
		}
	}

	return goEnv{
		Proxies:  parseProxyList(goproxy),
		NoProxy:  noProxy,
		ModCache: modCache,
	}
}

// proxyURLs returns the list of Go module proxies to try, in order.
func proxyURLs() []proxyEntry {
	return loadGoEnv().Proxies
}

// parseProxyList parses a GOPROXY value. Entries are separated by ',' (fall
// back to the next entry only on 404/410) or '|' (fall back on any error).
// "off" stops the list.
func parseProxyList(goproxy string) []proxyEntry {
	var entries []proxyEntry
	for goproxy != "" {
		var entry string
		anyError := false
		if i := strings.IndexAny(goproxy, ",|"); i >= 0 {
			entry = goproxy[:i]
			anyError = goproxy[i] == '|'
			goproxy = goproxy[i+1:]
		} else {
			entry, goproxy = goproxy, ""
		}
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if entry == "off" {
			break
		}
		entries = append(entries, proxyEntry{URL: entry, FallbackOnAnyError: anyError})
	}
	return entries
}

// licenseFileNames lists recognised license file names in order of preference.
// Matching is case-insensitive.
var licenseFileNames = []string{
	"LICENSE",
	"LICENSE.md",
	"LICENSE.txt",
	"LICENSE.markdown",
	"LICENSE.rst",
	"LICENCE",
	"LICENCE.md",
	"LICENCE.txt",
	"COPYING",
	"COPYING.md",
	"COPYING.txt",
	"UNLICENSE",
	"LICENSE-MIT",
	"LICENSE-APACHE",
	"LICENSE-2.0.txt",
	"MIT-LICENSE",
	"LICENSE.MIT",
}

var licenseFilePriority = func() map[string]int {
	m := make(map[string]int, len(licenseFileNames))
	for i, name := range licenseFileNames {
		m[strings.ToLower(name)] = i
	}
	return m
}()

// licenseNamePriority returns the preference rank of a license file name
// (lower is better), or -1 when the name is not a license file.
func licenseNamePriority(name string) int {
	if p, ok := licenseFilePriority[strings.ToLower(name)]; ok {
		return p
	}
	return -1
}

// Fetch populates the License field of every package that does not have one
// yet (packages with a --licence override are left alone).
// Licenses are looked up, in order: in local replacement directories, in the
// local module cache, and finally from the module proxy. Modules matching
// GONOPROXY/GOPRIVATE are never requested from a proxy.
// If info.Dir is set, the main module's license is detected from a local
// license file there.
func Fetch(ctx context.Context, info *packages.Info, opts Options) error {
	classifier, err := assets.DefaultClassifier()
	if err != nil {
		return fmt.Errorf("initializing license classifier: %w", err)
	}

	if info.Dir != "" && info.Main.License == "" {
		info.Main.License, _ = detectDirLicense(classifier, info.Dir, opts)
	}

	env := loadGoEnv()
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

	for i := range info.Deps {
		pkg := info.Deps[i].Effective()
		if pkg.License != "" {
			logVerbose(opts, "license for %s already set to %s, skipping detection", pkg.Path, pkg.License)
			continue
		}
		wg.Go(func() {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				pkg.License = "Unknown"
				return
			}
			defer func() { <-sem }()

			depCtx, depCancel := context.WithTimeout(ctx, depTimeout)
			defer depCancel()

			pkg.License, pkg.LicenseLink = detectLicense(depCtx, classifier, env, info.Dir, pkg, opts)
		})
	}

	wg.Wait()
	return nil
}

// detectLocalLicense returns the license of the license file in dir, or ""
// when there is none.
func detectLocalLicense(classifier *licenseclassifier.Classifier, dir string, opts Options) string {
	license, _ := detectDirLicense(classifier, dir, opts)
	return license
}

// detectDirLicense classifies the preferred license file in dir. It returns
// the license and the file name, or two empty strings when there is no
// license file.
func detectDirLicense(classifier *licenseclassifier.Classifier, dir string, opts Options) (license, file string) {
	name := findLicenseFile(dir)
	if name == "" {
		return "", ""
	}
	data, err := readLimited(filepath.Join(dir, name))
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: reading %s: %v\n", filepath.Join(dir, name), err)
		return "", ""
	}
	logVerbose(opts, "found license file: %s", filepath.Join(dir, name))
	return classifyLicense(classifier, data, opts), name
}

// findLicenseFile returns the best-ranked license file name in dir, or "".
func findLicenseFile(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	best, bestPrio := "", -1
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		p := licenseNamePriority(e.Name())
		if p >= 0 && (bestPrio < 0 || p < bestPrio) {
			best, bestPrio = e.Name(), p
		}
	}
	return best
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxLicenseFileSize))
}

func detectLicense(ctx context.Context, classifier *licenseclassifier.Classifier, env goEnv, baseDir string, pkg *packages.Package, opts Options) (license, link string) {
	if pkg.IsLocal() {
		dir := pkg.Path
		if !filepath.IsAbs(dir) && baseDir != "" {
			dir = filepath.Join(baseDir, dir)
		}
		license, _ = detectDirLicense(classifier, dir, opts)
		if license == "" {
			fmt.Fprintf(os.Stderr, "warning: no license file found in local replacement %s\n", dir)
			return "Unknown", ""
		}
		return license, ""
	}

	if license, file := detectModCacheLicense(classifier, env.ModCache, pkg, opts); file != "" {
		return license, buildLicenseLink(pkg.Path, pkg.Version, file)
	}

	if module.MatchPrefixPatterns(env.NoProxy, pkg.Path) {
		fmt.Fprintf(os.Stderr, "warning: %s@%s is private (GONOPROXY/GOPRIVATE) and not in the module cache; set its license with --licence\n",
			pkg.Path, pkg.Version)
		return "Unknown", ""
	}

	logVerbose(opts, "fetching license for %s@%s", pkg.Path, pkg.Version)

	zipPath, err := downloadModuleZip(ctx, env.Proxies, pkg.Path, pkg.Version, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: fetching %s@%s: %v\n", pkg.Path, pkg.Version, err)
		return "Unknown", ""
	}
	defer os.Remove(zipPath)

	content, licenseFile, err := extractLicenseFromZipFile(zipPath, pkg.Path, pkg.Version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: reading license for %s@%s: %v\n", pkg.Path, pkg.Version, err)
		return "Unknown", ""
	}
	if content == nil {
		logVerbose(opts, "no license file found in %s@%s", pkg.Path, pkg.Version)
		return "Unknown", ""
	}

	logVerbose(opts, "found license file %q in %s@%s", licenseFile, pkg.Path, pkg.Version)
	license = classifyLicense(classifier, content, opts)
	link = buildLicenseLink(pkg.Path, pkg.Version, licenseFile)
	return license, link
}

// modCacheDir returns the extracted module directory in the module cache.
func modCacheDir(modCache, modulePath, version string) (string, error) {
	if modCache == "" {
		return "", errors.New("module cache location unknown")
	}
	escPath, err := module.EscapePath(modulePath)
	if err != nil {
		return "", err
	}
	escVersion, err := module.EscapeVersion(version)
	if err != nil {
		return "", err
	}
	return filepath.Join(modCache, filepath.FromSlash(escPath)+"@"+escVersion), nil
}

// detectModCacheLicense looks for the module in the local module cache.
// file is empty when the module or its license file is not there.
func detectModCacheLicense(classifier *licenseclassifier.Classifier, modCache string, pkg *packages.Package, opts Options) (license, file string) {
	dir, err := modCacheDir(modCache, pkg.Path, pkg.Version)
	if err != nil {
		return "", ""
	}
	if _, err := os.Stat(dir); err != nil {
		return "", ""
	}
	logVerbose(opts, "using module cache for %s@%s", pkg.Path, pkg.Version)
	return detectDirLicense(classifier, dir, opts)
}

func buildLicenseLink(modulePath, version, licenseFile string) string {
	if licenseFile == "" {
		return ""
	}
	switch {
	case strings.HasPrefix(modulePath, "github.com/"):
		return fmt.Sprintf("https://%s/blob/%s/%s", modulePath, version, licenseFile)
	case strings.HasPrefix(modulePath, "gitlab.com/"):
		return fmt.Sprintf("https://%s/-/blob/%s/%s", modulePath, version, licenseFile)
	case strings.HasPrefix(modulePath, "gitea.com/") || strings.HasPrefix(modulePath, "codeberg.org/"):
		return fmt.Sprintf("https://%s/src/tag/%s/%s", modulePath, version, licenseFile)
	default:
		return fmt.Sprintf("https://pkg.go.dev/%s@%s?tab=licenses", modulePath, version)
	}
}

// statusError is a non-200 HTTP response from a proxy.
type statusError struct {
	URL  string
	Code int
}

func (e *statusError) Error() string {
	return fmt.Sprintf("HTTP %d for %s", e.Code, e.URL)
}

var errZipTooLarge = errors.New("module zip exceeds maximum size")

// isNotFound reports whether err means the proxy does not have the module.
func isNotFound(err error) bool {
	var se *statusError
	return errors.As(err, &se) && (se.Code == http.StatusNotFound || se.Code == http.StatusGone)
}

// isRetryable reports whether retrying the same proxy may succeed.
func isRetryable(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errZipTooLarge) {
		return false
	}
	if se, ok := errors.AsType[*statusError](err); ok {
		return se.Code >= 500 || se.Code == http.StatusTooManyRequests
	}
	return true // network error
}

// downloadModuleZip downloads the module zip into a temporary file and returns
// its path. The caller must remove the file.
func downloadModuleZip(ctx context.Context, proxies []proxyEntry, modulePath, version string, opts Options) (string, error) {
	escapedPath, err := module.EscapePath(modulePath)
	if err != nil {
		return "", fmt.Errorf("escaping module path %q: %w", modulePath, err)
	}
	escapedVersion, err := module.EscapeVersion(version)
	if err != nil {
		return "", fmt.Errorf("escaping module version %q: %w", version, err)
	}

	tmp, err := os.CreateTemp("", "go-sbom-*.zip")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	defer tmp.Close()

	var lastErr error
	for _, proxy := range proxies {
		if proxy.URL == "direct" {
			// "direct" means fetch from VCS; not supported here.
			lastErr = errors.New("module not available from any proxy (GOPROXY=direct is not supported)")
			continue
		}

		lastErr = fetchFromProxyWithRetry(ctx, proxy.URL, escapedPath, escapedVersion, tmp, opts)
		if lastErr == nil {
			return tmpPath, nil
		}
		if !isNotFound(lastErr) && !proxy.FallbackOnAnyError {
			break
		}
	}

	_ = os.Remove(tmpPath)
	if lastErr == nil {
		return "", fmt.Errorf("no proxy available for %s@%s", modulePath, version)
	}
	return "", lastErr
}

func fetchFromProxyWithRetry(ctx context.Context, proxyURL, escapedPath, escapedVersion string, dst *os.File, opts Options) error {
	var lastErr error
	for attempt := range maxRetries {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt-1))) * retryBackoff
			logVerbose(opts, "retry %d/%d for %s/@v/%s.zip from %s (backoff %s)",
				attempt+1, maxRetries, escapedPath, escapedVersion, proxyURL, backoff)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}

		lastErr = fetchFromProxy(ctx, proxyURL, escapedPath, escapedVersion, dst)
		if lastErr == nil {
			return nil
		}
		logVerbose(opts, "attempt %d/%d failed for %s/@v/%s.zip: %v",
			attempt+1, maxRetries, escapedPath, escapedVersion, lastErr)
		if !isRetryable(lastErr) {
			break
		}
	}
	return lastErr
}

// fetchFromProxy downloads the module zip into dst, replacing its contents.
func fetchFromProxy(ctx context.Context, proxyURL, escapedPath, escapedVersion string, dst *os.File) error {
	url := fmt.Sprintf("%s/%s/@v/%s.zip", strings.TrimRight(proxyURL, "/"), escapedPath, escapedVersion)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &statusError{URL: url, Code: resp.StatusCode}
	}

	if err := dst.Truncate(0); err != nil {
		return err
	}
	if _, err := dst.Seek(0, io.SeekStart); err != nil {
		return err
	}
	n, err := io.Copy(dst, io.LimitReader(resp.Body, maxZipFile+1))
	if err != nil {
		return err
	}
	if n > maxZipFile {
		return fmt.Errorf("%w (%d bytes) for %s", errZipTooLarge, int64(maxZipFile), url)
	}
	return nil
}

func extractLicenseFromZipFile(path, modulePath, version string) ([]byte, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, "", err
	}
	return extractLicenseFromZip(f, st.Size(), modulePath, version)
}

// extractLicenseFromZip returns the content and name of the preferred license
// file at the root of a module zip. content is nil when there is none.
func extractLicenseFromZip(r io.ReaderAt, size int64, modulePath, version string) ([]byte, string, error) {
	reader, err := zip.NewReader(r, size)
	if err != nil {
		return nil, "", fmt.Errorf("opening zip: %w", err)
	}

	prefix := modulePath + "@" + version + "/"

	var best *zip.File
	bestPrio := -1
	for _, f := range reader.File {
		if !isLicenseFile(f.Name, prefix) {
			continue
		}
		p := licenseNamePriority(strings.TrimPrefix(f.Name, prefix))
		if bestPrio < 0 || p < bestPrio {
			best, bestPrio = f, p
		}
	}
	if best == nil {
		return nil, "", nil
	}

	rc, err := best.Open()
	if err != nil {
		return nil, "", err
	}
	defer rc.Close()
	content, err := io.ReadAll(io.LimitReader(rc, maxLicenseFileSize))
	if err != nil {
		return nil, "", err
	}
	return content, strings.TrimPrefix(best.Name, prefix), nil
}

func isLicenseFile(name, prefix string) bool {
	rel, ok := strings.CutPrefix(name, prefix)
	if !ok || strings.Contains(rel, "/") {
		return false
	}
	return licenseNamePriority(rel) >= 0
}

// classifyLicense returns the license of a license file. A file can hold
// several licenses (gopkg.in/yaml.v3: MIT for code ported from libyaml,
// Apache-2.0 for the rest; vendored code under its own license). Every
// distinct license found is kept, in file order, joined with AND: the
// classifier can't tell "all of these apply" from "pick one", and AND is the
// safe reading for a license policy. A real dual license can be pinned with
// --licence (e.g. "MIT OR Apache-2.0").
func classifyLicense(classifier *licenseclassifier.Classifier, content []byte, opts Options) string {
	matches := slices.Clone(classifier.Match(content).Matches)
	slices.SortStableFunc(matches, func(a, b *licenseclassifier.Match) int { return a.StartLine - b.StartLine })

	var names []string
	for _, m := range matches {
		// Skip copyright notice matches — we want actual license types.
		if m.Name == "Copyright" {
			continue
		}
		logVerbose(opts, "  classifier match: %s (confidence: %.4f, lines %d-%d)", m.Name, m.Confidence, m.StartLine, m.EndLine)
		if opts.MinConfidence > 0 && m.Confidence < opts.MinConfidence {
			logVerbose(opts, "  rejected %s (confidence %.4f < threshold %.4f)", m.Name, m.Confidence, opts.MinConfidence)
			continue
		}
		if !slices.Contains(names, m.Name) {
			names = append(names, m.Name)
		}
	}

	if len(names) == 0 {
		return "Unknown"
	}
	license := strings.Join(names, " AND ")
	logVerbose(opts, "  classified as %s", license)
	return license
}
