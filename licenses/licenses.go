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
	"path"
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
	// module is the module being looked at; verbose lines are prefixed with
	// it, because modules are processed concurrently and their lines
	// interleave.
	module string
	// Order is the order in which several licenses of one module are
	// written ("MIT AND Apache-2.0"): licenses in Order first, in its order
	// (matched case-insensitively), then the others alphabetically. main
	// passes the allowed list, so the output follows the user's config.
	Order         []string
	MinConfidence float64
	Verbose       bool
}

// forModule returns opts for the verbose output about one module.
func (o Options) forModule(ref string) Options {
	o.module = ref
	return o
}

func logVerbose(opts Options, format string, args ...any) {
	if !opts.Verbose {
		return
	}
	if opts.module != "" {
		format = opts.module + ": " + format
	}
	fmt.Fprintf(os.Stderr, "verbose: "+format+"\n", args...)
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

// notLicenseExts are extensions of source and data files: license.go or
// licenses.json start like a license file name but hold no license text.
var notLicenseExts = []string{
	".go", ".s", ".c", ".h", ".cc", ".cpp", ".rs", ".py", ".js", ".ts", ".sh",
	".json", ".yml", ".yaml", ".toml", ".xml", ".csv", ".proto", ".tmpl", ".tpl", ".html",
	".mod", ".sum", ".png", ".jpg", ".svg", ".gif",
}

// isOtherLicenseName reports whether a top-level file that is not in
// licenseFileNames still looks like a license file (LICENSE.code,
// LICENSE-APACHE-2.0.txt, COPYING.LIB). Licenses of documentation and logos
// (LICENSE.docs, LICENSE-LOGO) are skipped: they don't cover the code that
// is built.
func isOtherLicenseName(name string) bool {
	n := strings.ToLower(name)
	if strings.Contains(n, "doc") || strings.Contains(n, "logo") || slices.Contains(notLicenseExts, path.Ext(n)) {
		return false
	}
	for _, prefix := range []string{"license", "licence", "copying", "unlicense"} {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	return false
}

// licenseCandidates picks the license files to classify among the files of a
// module (paths relative to the module root, "/"-separated). Their licenses
// are combined with AND, since a module can come with several:
// LICENSE-MIT + LICENSE-APACHE, LICENSE + LICENSE.libyaml (gopkg.in/yaml.v2,
// for ported code), LICENSE + LICENSE-THIRD-PARTY (vendored code).
//
//  1. every top-level license file: the well-known names (licenseFileNames)
//     first, in their order of preference, then other license-like names
//     (isOtherLicenseName) sorted by name;
//  2. if there is none, the REUSE layout: every LICENSES/*.txt.
//
// The first file is the one the license link points to.
func licenseCandidates(names []string) []string {
	var known, other, reuse []string
	for _, name := range names {
		dir, base := path.Split(name)
		switch {
		case dir == "" && licenseNamePriority(base) >= 0:
			known = append(known, name)
		case dir == "" && isOtherLicenseName(base):
			other = append(other, name)
		case strings.EqualFold(dir, "LICENSES/") && strings.EqualFold(path.Ext(base), ".txt"):
			reuse = append(reuse, name)
		}
	}
	slices.SortFunc(known, func(a, b string) int {
		if d := licenseNamePriority(a) - licenseNamePriority(b); d != 0 {
			return d
		}
		return strings.Compare(a, b)
	})
	slices.Sort(other)
	if top := slices.Concat(known, other); len(top) > 0 {
		return top
	}
	slices.Sort(reuse)
	return reuse
}

// licenseFile is a license file of a module: its path relative to the module
// root and its content (at most maxLicenseFileSize bytes).
type licenseFile struct {
	Name    string
	Content []byte
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
		info.Main.License, _, _ = detectDirLicense(classifier, info.Dir, opts.forModule(info.Main.Ref()))
	}

	env := loadGoEnv()
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

	for i := range info.Deps {
		pkg := info.Deps[i].Effective()
		// OS packages carry their license; local replacements of image binaries are not on disk.
		if pkg.Type != "" || (info.Image != nil && pkg.IsLocal()) {
			if pkg.License == "" {
				pkg.License = "Unknown"
			}
			continue
		}
		if pkg.License != "" {
			logVerbose(opts.forModule(pkg.Ref()), "license already set to %s, skipping detection", pkg.License)
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

			pkg.License, pkg.LicenseLink = detectLicense(depCtx, classifier, env, info.Dir, pkg, opts.forModule(pkg.Ref()))
		})
	}

	wg.Wait()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("stopped before every license was found, the rest are Unknown: %w", err)
	}
	return nil
}

// detectLocalLicense returns the license of the license file in dir, or ""
// when there is none.
func detectLocalLicense(classifier *licenseclassifier.Classifier, dir string, opts Options) string {
	license, _, _ := detectDirLicense(classifier, dir, opts)
	return license
}

// detectDirLicense classifies the license files in dir (see
// licenseCandidates). It returns the license, the first license file and,
// for an Unknown license, the reason. license is "" when dir has no license
// file.
func detectDirLicense(classifier *licenseclassifier.Classifier, dir string, opts Options) (license, file, problem string) {
	files := dirLicenseFiles(dir)
	if len(files) == 0 {
		return "", "", "no license file found"
	}
	for _, f := range files {
		logVerbose(opts, "found license file: %s", filepath.Join(dir, filepath.FromSlash(f.Name)))
	}
	license, problem = classifyFiles(classifier, files, opts)
	return license, files[0].Name, problem
}

// dirLicenseFiles reads the license files of the module in dir.
func dirLicenseFiles(dir string) []licenseFile {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		switch {
		case !e.IsDir():
			names = append(names, e.Name())
		case strings.EqualFold(e.Name(), "LICENSES"):
			sub, _ := os.ReadDir(filepath.Join(dir, e.Name()))
			for _, f := range sub {
				if !f.IsDir() {
					names = append(names, e.Name()+"/"+f.Name())
				}
			}
		}
	}
	var files []licenseFile
	for _, name := range licenseCandidates(names) {
		full := filepath.Join(dir, filepath.FromSlash(name))
		data, err := readLimited(full)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: reading %s: %v\n", full, err)
			continue
		}
		files = append(files, licenseFile{Name: name, Content: data})
	}
	return files
}

func readLimited(file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxLicenseFileSize))
}

// unknownLicense prints why the license of pkg could not be determined and
// returns "Unknown".
func unknownLicense(pkg *packages.Package, problem string) string {
	fmt.Fprintf(os.Stderr, "warning: %s: %s; set its license with --licence\n", pkg.Ref(), problem)
	return "Unknown"
}

func detectLicense(ctx context.Context, classifier *licenseclassifier.Classifier, env goEnv, baseDir string, pkg *packages.Package, opts Options) (license, link string) {
	if pkg.IsLocal() {
		dir := pkg.Path
		if !filepath.IsAbs(dir) && baseDir != "" {
			dir = filepath.Join(baseDir, dir)
		}
		license, _, problem := detectDirLicense(classifier, dir, opts)
		if license == "" || license == "Unknown" {
			return unknownLicense(pkg, problem+" in local replacement "+dir), ""
		}
		return license, ""
	}

	// A module in the module cache is complete: its license files are there
	// or nowhere, so there is no point in downloading it again.
	if dir, ok := modCacheModule(env.ModCache, pkg); ok {
		logVerbose(opts, "using module cache %s", dir)
		license, file, problem := detectDirLicense(classifier, dir, opts)
		if license == "" || license == "Unknown" {
			return unknownLicense(pkg, problem), ""
		}
		return license, buildLicenseLink(pkg.Path, pkg.Version, file)
	}

	if module.MatchPrefixPatterns(env.NoProxy, pkg.Path) {
		fmt.Fprintf(os.Stderr, "warning: %s@%s is private (GONOPROXY/GOPRIVATE) and not in the module cache; set its license with --licence\n",
			pkg.Path, pkg.Version)
		return "Unknown", ""
	}

	logVerbose(opts, "fetching module zip from the proxy")

	zipPath, err := downloadModuleZip(ctx, env.Proxies, pkg.Path, pkg.Version, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: fetching %s@%s: %v\n", pkg.Path, pkg.Version, err)
		return "Unknown", ""
	}
	defer os.Remove(zipPath)

	files, err := zipLicenseFilesFromPath(zipPath, pkg.Path, pkg.Version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: reading license for %s@%s: %v\n", pkg.Path, pkg.Version, err)
		return "Unknown", ""
	}
	if len(files) == 0 {
		return unknownLicense(pkg, "no license file found"), ""
	}
	for _, f := range files {
		logVerbose(opts, "found license file %s in the module zip", f.Name)
	}
	license, problem := classifyFiles(classifier, files, opts)
	if license == "Unknown" {
		return unknownLicense(pkg, problem), ""
	}
	return license, buildLicenseLink(pkg.Path, pkg.Version, files[0].Name)
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

// modCacheModule returns the module's directory in the module cache, if it
// has been extracted there.
func modCacheModule(modCache string, pkg *packages.Package) (string, bool) {
	dir, err := modCacheDir(modCache, pkg.Path, pkg.Version)
	if err != nil {
		return "", false
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return "", false
	}
	return dir, true
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

func zipLicenseFilesFromPath(zipPath, modulePath, version string) ([]licenseFile, error) {
	f, err := os.Open(zipPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return zipLicenseFiles(f, st.Size(), modulePath, version)
}

// zipLicenseFiles reads the license files (see licenseCandidates) of a module
// zip. It returns no files when the module has none.
func zipLicenseFiles(r io.ReaderAt, size int64, modulePath, version string) ([]licenseFile, error) {
	reader, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("opening zip: %w", err)
	}

	prefix := modulePath + "@" + version + "/"
	byName := make(map[string]*zip.File)
	var names []string
	for _, f := range reader.File {
		rel, ok := strings.CutPrefix(f.Name, prefix)
		if !ok || strings.HasSuffix(rel, "/") {
			continue
		}
		if dir, _ := path.Split(rel); dir == "" || strings.EqualFold(dir, "LICENSES/") {
			byName[rel] = f
			names = append(names, rel)
		}
	}

	var files []licenseFile
	for _, name := range licenseCandidates(names) {
		content, err := readZipFile(byName[name])
		if err != nil {
			return nil, err
		}
		files = append(files, licenseFile{Name: name, Content: content})
	}
	return files, nil
}

func readZipFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, maxLicenseFileSize))
}

// classifyFiles classifies license files and combines their licenses with
// AND (LICENSE.code + LICENSE.APACHE, or the files of a REUSE LICENSES/
// directory, all apply). For an Unknown result, problem says why.
func classifyFiles(classifier *licenseclassifier.Classifier, files []licenseFile, opts Options) (license, problem string) {
	var names, fileNames []string
	rejected := false
	for _, f := range files {
		found, low := classifyNames(classifier, f.Content, opts)
		rejected = rejected || low
		for _, n := range found {
			if !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
		fileNames = append(fileNames, f.Name)
	}
	if len(names) > 0 {
		sortLicenses(names, opts.Order)
		license = strings.Join(names, " AND ")
		logVerbose(opts, "  classified as %s", license)
		return license, ""
	}
	if rejected {
		return "Unknown", fmt.Sprintf("license in %s is below --min-confidence %.2f", strings.Join(fileNames, ", "), opts.MinConfidence)
	}
	return "Unknown", "license file " + strings.Join(fileNames, ", ") + " not recognised by the classifier"
}

// sortLicenses sorts names by their position in order; names that are not
// in order go last, alphabetically. AND is commutative, so this only makes
// the same set of licenses always read the same.
func sortLicenses(names, order []string) {
	rank := func(name string) int {
		for i, o := range order {
			if strings.EqualFold(o, name) {
				return i
			}
		}
		return len(order)
	}
	slices.SortStableFunc(names, func(a, b string) int {
		if d := rank(a) - rank(b); d != 0 {
			return d
		}
		return strings.Compare(a, b)
	})
}

// classifyNames returns the licenses found in the content of a license file.
// A file can hold several licenses (gopkg.in/yaml.v3: MIT for code ported
// from libyaml, Apache-2.0 for the rest; vendored code under its own
// license): every distinct license is returned, in file order. rejected
// reports matches dropped by --min-confidence.
func classifyNames(classifier *licenseclassifier.Classifier, content []byte, opts Options) (names []string, rejected bool) {
	matches := slices.Clone(classifier.Match(content).Matches)
	slices.SortStableFunc(matches, func(a, b *licenseclassifier.Match) int { return a.StartLine - b.StartLine })

	for _, m := range matches {
		// Skip copyright notice matches — we want actual license types.
		if m.Name == "Copyright" {
			continue
		}
		logVerbose(opts, "  classifier match: %s (confidence: %.4f, lines %d-%d)", m.Name, m.Confidence, m.StartLine, m.EndLine)
		if opts.MinConfidence > 0 && m.Confidence < opts.MinConfidence {
			logVerbose(opts, "  rejected %s (confidence %.4f < threshold %.4f)", m.Name, m.Confidence, opts.MinConfidence)
			rejected = true
			continue
		}
		if !slices.Contains(names, m.Name) {
			names = append(names, m.Name)
		}
	}
	return names, rejected
}

// classifyLicense returns the license of one license file, or "Unknown".
// Several licenses are joined with AND: the classifier can't tell "all of
// these apply" from "pick one", and AND is the safe reading for a license
// policy. A real dual license can be pinned with --licence (e.g. "MIT OR
// Apache-2.0").
func classifyLicense(classifier *licenseclassifier.Classifier, content []byte, opts Options) string {
	license, _ := classifyFiles(classifier, []licenseFile{{Content: content}}, opts)
	return license
}
