package args

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/oktalz/go-sbom/logo"
	"github.com/oktalz/go-sbom/output"
	"github.com/oktalz/go-sbom/version"
	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
	"github.com/peterbourgon/ff/v4/ffval"
	"github.com/peterbourgon/ff/v4/ffyaml"
)

// DefaultConfigFiles are looked up in the current directory when no config
// file is named; at most one of them may exist.
var DefaultConfigFiles = []string{".go-sbom.yml", ".go-sbom.yaml"}

// EnvPrefix is the prefix of the environment variables that set flags:
// --min-confidence is GO_SBOM_MIN_CONFIDENCE. The prefix keeps generic names
// such as FILE or VERSION in the environment from changing what go-sbom does.
const EnvPrefix = "GO_SBOM"

func envVars() ff.Option { return ff.WithEnvVarPrefix(EnvPrefix) }

// Config holds the command line arguments. Every flag can also be set in the
// config file (key = long flag name) or an environment variable
// (GO_SBOM_ + upper-case long name, dashes as underscores).
// Precedence: command line > environment > config file.
type Config struct {
	SPDXVersion   string           `ff:"long: spdx-version,             default: 2, usage: 'SPDX version used by --format spdx and .spdx.json: 2 (SPDX 2.3) or 3 (SPDX 3.0.1)'"`
	Allowed       ffval.StringList `ff:"short: a, long: allowed,        usage: 'allowed licenses for --check, comma-separated or repeatable (e.g. MIT,Apache-2.0)'"`
	Exclude       ffval.StringList `ff:"short: e, long: exclude,        usage: 'module path prefixes or globs to skip in --check, comma-separated or repeatable (e.g. company.com/internal)'"`
	Licence       ffval.StringList `ff:"long: licence,                  usage: 'set license for a package (e.g. company.com/pkg:MIT, repeatable)'"`
	File          string           `ff:"short: f, long: file,           usage: 'file to analyze (binary or go.mod); can also be given as the first argument'"`
	Image         string           `ff:"long: image,                    usage: 'container image to analyze, pulled from its registry (e.g. alpine:3.20)'"`
	ImageArchive  string           `ff:"long: image-archive,            usage: 'container image to analyze, from a docker save tarball'"`
	Platform      string           `ff:"long: platform,                 usage: 'platform of a multi-platform --image, as os/arch[/variant] (default: linux/<arch of go-sbom>)'"`
	Output        string           `ff:"short: o, long: output,         usage: 'output file (.txt, .yml, .csv, .json, .cyclonedx.json or .cdx.json, .spdx.json, .spdx2.json, .spdx3.json)'"`
	Format        string           `ff:"long: format,                   usage: 'output format override (text, csv, yaml, json, cyclonedx, spdx, spdx2, spdx3)'"`
	Config        string           `ff:"short: c, long: config,         usage: 'YAML config file with flag values (default: .go-sbom.yml or .go-sbom.yaml)'"`
	JUnitFile     string           `ff:"long: junit-file,               usage: 'write a JUnit XML report of the license check (used with --check)'"`
	MinConfidence float64          `ff:"long: min-confidence,           usage: 'minimum confidence threshold for license classification (0.0-1.0)'"`
	ImageTimeout  time.Duration    `ff:"long: image-timeout,            default: 10m, usage: 'time limit for pulling and reading the image (0 for none)'"`
	Check         bool             `ff:"long: check,                    usage: 'check licenses against --allowed and exit 2 on violations (no SBOM is written)'"`
	Version       bool             `ff:"short: v, long: version,        usage: 'show version'"`
	Help          bool             `ff:"short: h, long: help,           usage: 'show this help message'"`
	Links         bool             `ff:"short: l, long: links,          usage: 'include links to license files in output'"`
	Verbose       bool             `ff:"long: verbose,                  usage: 'enable verbose/debug logging'"`
}

func Get() Config {
	parsed, err := parse(os.Args[1:])
	configuration, osArgsFF := parsed.cfg, parsed.fs
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
		fmt.Fprintln(os.Stderr, ffhelp.Flags(osArgsFF))
		os.Exit(1) //revive:disable:deep-exit
	}
	if configuration.Help {
		fmt.Println(logo.Logo)
		fmt.Println(ffhelp.Flags(osArgsFF))
		os.Exit(0)
	}

	if configuration.Version {
		fmt.Println(logo.Logo)
		fmt.Println(version.Repo, version.Version, version.CommitDate)
		os.Exit(0)
	}

	if err := resolveFile(&configuration, parsed.positional, parsed.cliFile); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if err := selectInput(&configuration, parsed.cliInputs, parsed.envInputs); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	warnings, err := policyProblem(parsed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, w)
	}

	if _, err := output.SPDXFormat(configuration.SPDXVersion); err != nil {
		fmt.Fprintf(os.Stderr, "error: --spdx-version: %v\n", err)
		os.Exit(1)
	}
	if f := configuration.Format; f != "" && !output.IsFormat(f) {
		fmt.Fprintf(os.Stderr, "error: invalid --format %q (use %s)\n", f, strings.Join(output.Formats, ", "))
		os.Exit(1)
	}

	if configuration.MinConfidence < 0 || configuration.MinConfidence > 1 {
		fmt.Fprintln(os.Stderr, "error: --min-confidence must be between 0.0 and 1.0")
		os.Exit(1)
	}

	return configuration
}

type parseResult struct {
	fs         *ff.FlagSet
	cliFile    string // --file as given on the command line (not from env)
	positional []string
	cliInputs  []string // inputs (see [inputs]) given on the command line
	envInputs  []string // inputs given on the command line or in the environment
	cfg        Config
	// allowedOutsideConfig / excludeOutsideConfig are true when --allowed /
	// --exclude came from the command line or the environment rather than the
	// config file.
	allowedOutsideConfig bool
	excludeOutsideConfig bool
}

func parseOnce(args []string, opts ...ff.Option) (Config, *ff.FlagSet, error) {
	var cfg Config
	fs := ff.NewFlagSet("go-sbom")
	if err := fs.AddStruct(&cfg); err != nil {
		panic(err)
	}
	err := ff.Parse(fs, args, opts...)
	return cfg, fs, err
}

// parse parses args, allowing flags before and after positional arguments
// (`go-sbom go.mod -o out.csv`). ff, like the standard flag package, stops at
// the first non-flag argument, so that argument is set aside and the rest is
// parsed again with a fresh flag set. Everything after "--" is positional.
// Positional arguments are found without environment variables, so that
// only the command line counts as "given twice"; environment variables are
// applied in a final parse of the flag arguments.
func parse(args []string) (parseResult, error) {
	var positional []string
	for {
		cfg, fs, err := parseOnce(args)
		if err != nil {
			return parseResult{cfg: cfg, fs: fs}, err
		}

		rest := fs.GetArgs()
		consumed := args[:len(args)-len(rest)]
		if len(rest) == 0 || (len(consumed) > 0 && consumed[len(consumed)-1] == "--") {
			positional = append(positional, rest...)
			args = consumed
			break
		}
		positional = append(positional, rest[0])
		args = append(slices.Clip(consumed), rest[1:]...)
	}

	cliCfg, _, _ := parseOnce(args)
	envCfg, _, _ := parseOnce(args, envVars())
	configFile, err := resolveConfigFile(args)
	if err != nil {
		cfg, fs, _ := parseOnce(args)
		return parseResult{cfg: cfg, fs: fs}, err
	}
	opts := []ff.Option{envVars()}
	if configFile != "" {
		opts = append(opts, ff.WithConfigFile(configFile), ff.WithConfigFileParser(ffyaml.Parse))
	}
	cfg, fs, err := parseOnce(args, opts...)
	cfg.Config = configFile
	cliInputs := inputs(&cliCfg)
	if len(positional) > 0 && cliCfg.File == "" {
		cliInputs = append([]string{"file"}, cliInputs...)
	}
	return parseResult{
		cfg: cfg, fs: fs, positional: positional, cliFile: cliCfg.File,
		cliInputs: cliInputs, envInputs: inputs(&envCfg),
		allowedOutsideConfig: envCfg.Allowed.IsSet(), excludeOutsideConfig: envCfg.Exclude.IsSet(),
	}, err
}

// policyProblem reports a misconfigured license check: --check without an
// allowed list is an error; --allowed or --exclude given on the command line
// or in the environment without --check gets a warning, since they do nothing
// then. Values from the config file are silently kept for later --check runs.
func policyProblem(parsed parseResult) (warnings []string, err error) {
	if parsed.cfg.Check {
		if len(SplitList(parsed.cfg.Allowed.Get())) == 0 {
			return nil, errors.New("--check needs allowed licenses (--allowed or allowed: in the config file)")
		}
		return nil, nil
	}
	if parsed.allowedOutsideConfig {
		warnings = append(warnings, "warning: --allowed has no effect without --check; writing the SBOM instead of checking licenses")
	}
	if parsed.excludeOutsideConfig {
		warnings = append(warnings, "warning: --exclude has no effect without --check; the SBOM lists all packages")
	}
	return warnings, nil
}

// resolveConfigFile returns the config file to read, or "" for none.
// A file named with --config (or GO_SBOM_CONFIG) must exist. Otherwise the first existing file of
// [DefaultConfigFiles] is used, and having more than one is an error.
func resolveConfigFile(args []string) (string, error) {
	cfg, fs, err := parseOnce(args, envVars())
	if err != nil {
		return "", err
	}
	if f, ok := fs.GetFlag("config"); ok && f.IsSet() && cfg.Config != "" {
		if _, err := os.Stat(cfg.Config); err != nil {
			return "", fmt.Errorf("config file: %w", err)
		}
		return cfg.Config, nil
	}

	var found []string
	for _, name := range DefaultConfigFiles {
		if _, err := os.Stat(name); err == nil {
			found = append(found, name)
		}
	}
	switch len(found) {
	case 0:
		return "", nil
	case 1:
		return found[0], nil
	default:
		return "", fmt.Errorf("found both %s; keep one, or choose with --config", strings.Join(found, " and "))
	}
}

// SplitList flattens repeatable, comma-separated flag values
// (["MIT,ISC", " BSD-3-Clause "] -> [MIT ISC BSD-3-Clause]).
func SplitList(values []string) []string {
	var out []string
	for _, v := range values {
		for item := range strings.SplitSeq(v, ",") {
			if item = strings.TrimSpace(item); item != "" {
				out = append(out, item)
			}
		}
	}
	return out
}

// resolveFile takes the file to analyze from the first positional argument.
// The positional argument overrides a --file value from the environment, but
// conflicts with a different --file given on the command line (cliFile).
func resolveFile(cfg *Config, positional []string, cliFile string) error {
	switch {
	case len(positional) == 0:
		return nil
	case len(positional) > 1:
		return fmt.Errorf("expected at most one file argument, got %d: %s", len(positional), strings.Join(positional, " "))
	case cliFile != "" && cliFile != positional[0]:
		return fmt.Errorf("file given twice: --file %q and argument %q", cliFile, positional[0])
	default:
		cfg.File = positional[0]
		return nil
	}
}

// inputs names the flags of the analyzed inputs set in c.
func inputs(c *Config) []string {
	var out []string
	for _, in := range []struct{ flag, value string }{
		{"file", c.File}, {"image", c.Image}, {"image-archive", c.ImageArchive},
	} {
		if in.value != "" {
			out = append(out, in.flag)
		}
	}
	return out
}

// selectInput keeps the input of the strongest source (command line, then
// environment, then config file), so a config file's file: does not block --image.
// Two inputs from that source are an error.
func selectInput(cfg *Config, cliInputs, envInputs []string) error {
	keep := cliInputs
	if len(keep) == 0 {
		keep = envInputs
	}
	if len(keep) == 0 {
		keep = inputs(cfg)
	}
	switch len(keep) {
	case 0:
		return errors.New("nothing to analyze: give a file, --image or --image-archive")
	case 1:
	default:
		return fmt.Errorf("--%s and --%s are mutually exclusive", keep[0], keep[1])
	}
	if keep[0] != "file" {
		cfg.File = ""
	}
	if keep[0] != "image" {
		cfg.Image = ""
	}
	if keep[0] != "image-archive" {
		cfg.ImageArchive = ""
	}
	return nil
}
