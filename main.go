package main

//go:generate go run ./cmd/doc-options

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/oktalz/go-sbom/args"
	"github.com/oktalz/go-sbom/licenses"
	"github.com/oktalz/go-sbom/output"
	"github.com/oktalz/go-sbom/packages"
	"github.com/oktalz/go-sbom/version"
	"github.com/oktalz/junit-report"
	"golang.org/x/mod/module"
)

// Exit codes for different error conditions.
const (
	exitUsage     = 1
	exitViolation = 2
)

func main() {
	version.Set()

	if err := godotenv.Overload(".env"); err != nil {
		if _, statErr := os.Stat(".env"); statErr == nil {
			fmt.Fprintf(os.Stderr, "warning: .env file exists but could not be parsed: %v\n", err)
		}
	}

	cfg := args.Get()

	file := cfg.File
	if file == "" {
		fmt.Fprintln(os.Stderr, "error: file argument is required")
		os.Exit(exitUsage)
	}

	info, err := packages.Read(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitUsage)
	}

	if info.CGOEnabled {
		fmt.Fprintln(os.Stderr, "warning: binary was built with CGO_ENABLED=1; C library dependencies are not tracked in the SBOM")
	}

	// Excludes and overrides are applied before license detection so that
	// excluded or overridden (typically private) modules are never fetched.
	// The license check runs only with --check; otherwise allowed/exclude
	// (typically kept in .go-sbom.yml) are ignored and the SBOM is written.
	policyMode := cfg.Check
	allowedList := args.SplitList(cfg.Allowed.Get())
	if exclude := args.SplitList(cfg.Exclude.Get()); policyMode && len(exclude) > 0 {
		excludeDeps(info, strings.Join(exclude, ","))
	}
	if cfg.Licence.IsSet() {
		applyLicenceOverrides(info, cfg.Licence.Get())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	licenseOpts := licenses.Options{
		MinConfidence: cfg.MinConfidence,
		Verbose:       cfg.Verbose,
	}

	if err := licenses.Fetch(ctx, info, licenseOpts); err != nil {
		fmt.Fprintf(os.Stderr, "warning: license detection: %v\n", err)
	}

	if policyMode {
		allowed := make(map[string]bool, len(allowedList))
		for _, l := range allowedList {
			allowed[l] = true
		}

		var violations []packages.Package
		for _, dep := range info.Deps {
			if !allowed[dep.Effective().License] {
				violations = append(violations, dep)
			}
		}

		if cfg.JUnitFile != "" {
			writeJUnit(info, violations, allowed, cfg.JUnitFile)
		}

		if len(violations) > 0 {
			fmt.Fprintf(os.Stderr, "license policy violation: %d package(s) with disallowed licenses\n\n", len(violations))
			for i := range violations {
				pkg := violations[i].Effective()
				fmt.Fprintf(os.Stderr, "  %s: %s\n", pkg.Ref(), pkg.License)
			}
			os.Exit(exitViolation)
		}
		return
	}

	format, err := output.ResolveFormat(cfg.Output, cfg.Format, cfg.SPDXVersion)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitUsage)
	}
	if err := output.Write(info, cfg.Output, format, cfg.Links); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitUsage)
	}
}

func writeJUnit(info *packages.Info, violations []packages.Package, allowed map[string]bool, junitFile string) {
	violationSet := make(map[string]bool)
	for i := range violations {
		violationSet[violations[i].Effective().Path] = true
	}

	ts := junit.NewTestSuites()
	suite := ts.AddSuite("go-sbom license check")

	for i := range info.Deps {
		pkg := info.Deps[i].Effective()
		name := pkg.Ref()
		if violationSet[pkg.Path] {
			suite.AddMessageFailed(pkg.Path, name,
				fmt.Sprintf("license %q is not in allowed list: %s",
					pkg.License, strings.Join(sortedKeys(allowed), ", ")))
		} else {
			suite.AddMessageOK(pkg.Path, name, pkg.License)
		}
	}

	if err := ts.Write(junitFile); err != nil {
		fmt.Fprintf(os.Stderr, "warning: writing JUnit report: %v\n", err)
	}
}

// excludeDeps removes dependencies matching any of the comma-separated
// patterns. Patterns use GOPRIVATE syntax: a pattern matches a module path
// and everything below it (company.com/internal matches
// company.com/internal/pkg) and may contain globs (*.corp.example.com).
func excludeDeps(info *packages.Info, exclude string) {
	var patterns []string
	for e := range strings.SplitSeq(exclude, ",") {
		if e = strings.TrimSpace(e); e != "" {
			patterns = append(patterns, e)
		}
	}
	globs := strings.Join(patterns, ",")
	info.Deps = slices.DeleteFunc(info.Deps, func(dep packages.Package) bool {
		return module.MatchPrefixPatterns(globs, dep.Effective().Path)
	})
}

func applyLicenceOverrides(info *packages.Info, overrides []string) {
	m := make(map[string]string, len(overrides))
	for _, o := range overrides {
		idx := strings.LastIndex(o, ":")
		if idx <= 0 {
			fmt.Fprintf(os.Stderr, "warning: invalid --licence format %q (expected package:license)\n", o)
			continue
		}
		m[o[:idx]] = o[idx+1:]
	}
	if lic, ok := m[info.Main.Path]; ok {
		info.Main.License = lic
	}
	for i := range info.Deps {
		pkg := info.Deps[i].Effective()
		if lic, ok := m[pkg.Path]; ok {
			pkg.License = lic
		}
	}
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
