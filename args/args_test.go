package args

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// clearFlagEnv unsets the environment variables ff maps onto flags.
func clearFlagEnv(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir()) // no stray .go-sbom.yml
	for _, name := range []string{
		"CONFIG", "FILE", "OUTPUT", "FORMAT", "ALLOWED", "EXCLUDE", "LICENCE", "CHECK",
		"JUNIT_FILE", "SPDX_VERSION", "MIN_CONFIDENCE", "VERSION", "HELP", "LINKS", "VERBOSE",
		"IMAGE", "IMAGE_ARCHIVE", "PLATFORM", "IMAGE_TIMEOUT",
	} {
		name = EnvPrefix + "_" + name
		t.Setenv(name, "") // registers restore on cleanup
		_ = os.Unsetenv(name)
	}
}

func TestResolveFile(t *testing.T) {
	tests := []struct {
		name       string
		file       string // value after parsing (flag or env)
		cliFile    string // value given on the command line
		positional []string
		want       string
		wantErr    bool
	}{
		{name: "flag only", file: "go.mod", cliFile: "go.mod", want: "go.mod"},
		{name: "positional only", positional: []string{"bin/app"}, want: "bin/app"},
		{name: "same in both", file: "go.mod", cliFile: "go.mod", positional: []string{"go.mod"}, want: "go.mod"},
		{name: "conflict", file: "go.mod", cliFile: "go.mod", positional: []string{"bin/app"}, wantErr: true},
		{name: "positional overrides env", file: "from-env", positional: []string{"bin/app"}, want: "bin/app"},
		{name: "too many", positional: []string{"a", "b"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{File: tt.file}
			err := resolveFile(&cfg, tt.positional, tt.cliFile)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && cfg.File != tt.want {
				t.Errorf("File = %q, want %q", cfg.File, tt.want)
			}
		})
	}
}

func TestParseInterspersed(t *testing.T) {
	clearFlagEnv(t)
	tests := []struct {
		name       string
		args       []string
		file       string
		output     string
		licences   []string
		positional []string
		links      bool
	}{
		{name: "file first", args: []string{"go.mod", "-o", "out.csv", "-l"}, positional: []string{"go.mod"}, output: "out.csv", links: true},
		{name: "file last", args: []string{"-l", "-o", "out.csv", "go.mod"}, positional: []string{"go.mod"}, output: "out.csv", links: true},
		{
			name:       "file middle",
			args:       []string{"-o", "out.csv", "go.mod", "--licence", "a:MIT", "--licence", "b:ISC"},
			positional: []string{"go.mod"}, output: "out.csv", licences: []string{"a:MIT", "b:ISC"},
		},
		{name: "flag only", args: []string{"-f", "go.mod"}, file: "go.mod"},
		{name: "double dash", args: []string{"-l", "--", "-weird-name"}, positional: []string{"-weird-name"}, links: true},
		{name: "two positional", args: []string{"a", "-l", "b"}, positional: []string{"a", "b"}, links: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := parse(tt.args)
			if err != nil {
				t.Fatal(err)
			}
			cfg, positional := parsed.cfg, parsed.positional
			if cfg.File != tt.file || cfg.Output != tt.output || cfg.Links != tt.links {
				t.Errorf("cfg = file %q output %q links %v, want %q %q %v", cfg.File, cfg.Output, cfg.Links, tt.file, tt.output, tt.links)
			}
			if !slices.Equal(cfg.Licence.Get(), tt.licences) {
				t.Errorf("licences = %v, want %v", cfg.Licence.Get(), tt.licences)
			}
			if !slices.Equal(positional, tt.positional) {
				t.Errorf("positional = %v, want %v", positional, tt.positional)
			}
		})
	}
}

func TestParseEnvAndCLI(t *testing.T) {
	clearFlagEnv(t)
	t.Setenv("GO_SBOM_FILE", "from-env")
	t.Setenv("GO_SBOM_OUTPUT", "env.csv")

	parsed, err := parse([]string{"go.mod", "-o", "cli.csv"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.cliFile != "" || parsed.cfg.File != "from-env" || parsed.cfg.Output != "cli.csv" {
		t.Errorf("cliFile %q, File %q, Output %q; want \"\", from-env, cli.csv", parsed.cliFile, parsed.cfg.File, parsed.cfg.Output)
	}
	if err := resolveFile(&parsed.cfg, parsed.positional, parsed.cliFile); err != nil || parsed.cfg.File != "go.mod" {
		t.Errorf("positional should override env FILE: File %q, err %v", parsed.cfg.File, err)
	}
}

func TestParseUnknownFlag(t *testing.T) {
	if _, err := parse([]string{"go.mod", "--bogus"}); err == nil {
		t.Error("expected error for unknown flag")
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg := Config{}
	if cfg.File != "" {
		t.Errorf("File default should be empty, got %q", cfg.File)
	}
	if cfg.Output != "" {
		t.Errorf("Output default should be empty, got %q", cfg.Output)
	}
	if cfg.Format != "" {
		t.Errorf("Format default should be empty, got %q", cfg.Format)
	}
	if cfg.MinConfidence != 0 {
		t.Errorf("MinConfidence default should be 0, got %f", cfg.MinConfidence)
	}
	if cfg.Verbose {
		t.Error("Verbose default should be false")
	}
	if cfg.Links {
		t.Error("Links default should be false")
	}
	if cfg.Version {
		t.Error("Version default should be false")
	}
	if cfg.Help {
		t.Error("Help default should be false")
	}
}

func TestConfigLicenceStringList(t *testing.T) {
	cfg := Config{}

	// StringList should not be set by default
	if cfg.Licence.IsSet() {
		t.Error("Licence should not be set by default")
	}
}

func writeConfig(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const sampleConfig = `file: go.mod
output: from-config.csv
allowed:
  - MIT
  - Apache-2.0,ISC
exclude: company.com/internal
licence:
  - company.com/a:MIT
  - company.com/b:Proprietary
min-confidence: 0.8
links: true
`

func TestParseConfigFile(t *testing.T) {
	clearFlagEnv(t)
	writeConfig(t, ".go-sbom.yml", sampleConfig)

	parsed, err := parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := parsed.cfg
	if cfg.File != "go.mod" || cfg.Output != "from-config.csv" || cfg.MinConfidence != 0.8 || !cfg.Links {
		t.Errorf("cfg = %+v", cfg)
	}
	if got := SplitList(cfg.Allowed.Get()); !slices.Equal(got, []string{"MIT", "Apache-2.0", "ISC"}) {
		t.Errorf("allowed = %v", got)
	}
	if got := cfg.Exclude.Get(); !slices.Equal(got, []string{"company.com/internal"}) {
		t.Errorf("exclude = %v", got)
	}
	if got := cfg.Licence.Get(); !slices.Equal(got, []string{"company.com/a:MIT", "company.com/b:Proprietary"}) {
		t.Errorf("licence = %v", got)
	}
}

func TestParseEnvNeedsPrefix(t *testing.T) {
	clearFlagEnv(t)
	t.Setenv("FILE", "unprefixed")
	t.Setenv("VERSION", "true")

	parsed, err := parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.cfg.File != "" || parsed.cfg.Version {
		t.Errorf("env vars without the %s_ prefix must be ignored: File %q, Version %v", EnvPrefix, parsed.cfg.File, parsed.cfg.Version)
	}
}

func TestParseConfigPrecedence(t *testing.T) {
	clearFlagEnv(t)
	writeConfig(t, ".go-sbom.yml", sampleConfig)
	t.Setenv("GO_SBOM_ALLOWED", "BSD-3-Clause")

	parsed, err := parse([]string{"bin/app", "-o", "cli.csv", "--licence", "x:MIT"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := parsed.cfg
	if cfg.Output != "cli.csv" {
		t.Errorf("command line should beat config: output = %q", cfg.Output)
	}
	if got := cfg.Allowed.Get(); !slices.Equal(got, []string{"BSD-3-Clause"}) {
		t.Errorf("env should beat config: allowed = %v", got)
	}
	if got := cfg.Licence.Get(); !slices.Equal(got, []string{"x:MIT"}) {
		t.Errorf("command line list should replace config list: licence = %v", got)
	}
	if err := resolveFile(&cfg, parsed.positional, parsed.cliFile); err != nil || cfg.File != "bin/app" {
		t.Errorf("positional should beat config file: File = %q, err %v", cfg.File, err)
	}
}

func TestParseExplicitConfig(t *testing.T) {
	clearFlagEnv(t)
	writeConfig(t, "custom.yml", "output: custom.csv\n")

	parsed, err := parse([]string{"--config", "custom.yml"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.cfg.Output != "custom.csv" {
		t.Errorf("output = %q, want custom.csv", parsed.cfg.Output)
	}

	if _, err := parse([]string{"-c", "missing.yml"}); err == nil {
		t.Error("explicitly named missing config file should be an error")
	}
	if _, err := parse(nil); err != nil {
		t.Errorf("missing default config file should be fine: %v", err)
	}
}

func TestParseConfigYAMLExtension(t *testing.T) {
	clearFlagEnv(t)
	writeConfig(t, ".go-sbom.yaml", "output: from-yaml.csv\n")

	parsed, err := parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.cfg.Output != "from-yaml.csv" || parsed.cfg.Config != ".go-sbom.yaml" {
		t.Errorf("output = %q, config = %q; want from-yaml.csv from .go-sbom.yaml", parsed.cfg.Output, parsed.cfg.Config)
	}
}

func TestParseConfigBothExtensions(t *testing.T) {
	clearFlagEnv(t)
	writeConfig(t, ".go-sbom.yml", "output: a.csv\n")
	writeConfig(t, ".go-sbom.yaml", "output: b.csv\n")

	if _, err := parse(nil); err == nil {
		t.Error("having both .go-sbom.yml and .go-sbom.yaml should be an error")
	}
	parsed, err := parse([]string{"-c", ".go-sbom.yaml"})
	if err != nil {
		t.Fatalf("--config should resolve the ambiguity: %v", err)
	}
	if parsed.cfg.Output != "b.csv" {
		t.Errorf("output = %q, want b.csv", parsed.cfg.Output)
	}
}

func TestParseConfigUnknownKey(t *testing.T) {
	clearFlagEnv(t)
	writeConfig(t, ".go-sbom.yml", "alowed: MIT\n")
	if _, err := parse(nil); err == nil {
		t.Error("unknown config key should be an error")
	}
}

func TestParseJUnitFile(t *testing.T) {
	clearFlagEnv(t)

	t.Setenv("GO_SBOM_JUNIT_FILE", "env.xml")
	if parsed, err := parse(nil); err != nil || parsed.cfg.JUnitFile != "env.xml" {
		t.Errorf("GO_SBOM_JUNIT_FILE env: JUnitFile = %q, err %v", parsed.cfg.JUnitFile, err)
	}
	if parsed, err := parse([]string{"--junit-file", "cli.xml"}); err != nil || parsed.cfg.JUnitFile != "cli.xml" {
		t.Errorf("--junit-file should beat env: JUnitFile = %q, err %v", parsed.cfg.JUnitFile, err)
	}

	_ = os.Unsetenv("GO_SBOM_JUNIT_FILE")
	writeConfig(t, ".go-sbom.yml", "junit-file: config.xml\n")
	if parsed, err := parse(nil); err != nil || parsed.cfg.JUnitFile != "config.xml" {
		t.Errorf("junit-file in config: JUnitFile = %q, err %v", parsed.cfg.JUnitFile, err)
	}
}

func TestPolicyProblem(t *testing.T) {
	tests := []struct {
		name        string
		config      string
		env         string
		args        []string
		wantWarning int
		wantErr     bool
	}{
		{name: "allowed in config, no check", config: "allowed: [MIT]\n"},
		{name: "allowed in config, check", config: "allowed: [MIT]\n", args: []string{"--check"}},
		{name: "check in config", config: "allowed: [MIT]\ncheck: true\n"},
		{name: "check without allowed", args: []string{"--check"}, wantErr: true},
		{name: "allowed flag without check", args: []string{"--allowed", "MIT"}, wantWarning: 1},
		{name: "allowed env without check", env: "MIT", wantWarning: 1},
		{name: "allowed flag with check", args: []string{"--allowed", "MIT", "--check"}},
		{name: "exclude in config, no check", config: "exclude: [company.com]\n"},
		{name: "exclude flag without check", args: []string{"--exclude", "company.com"}, wantWarning: 1},
		{name: "exclude flag with check", config: "allowed: [MIT]\n", args: []string{"-e", "company.com", "--check"}},
		{name: "allowed and exclude without check", args: []string{"-a", "MIT", "-e", "company.com"}, wantWarning: 2},
		{name: "nothing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearFlagEnv(t)
			if tt.config != "" {
				writeConfig(t, ".go-sbom.yml", tt.config)
			}
			if tt.env != "" {
				t.Setenv("GO_SBOM_ALLOWED", tt.env)
			}
			parsed, err := parse(tt.args)
			if err != nil {
				t.Fatal(err)
			}
			warnings, err := policyProblem(parsed)
			if (err != nil) != tt.wantErr || len(warnings) != tt.wantWarning {
				t.Errorf("warnings %q, err %v; want %d warning(s), err %v", warnings, err, tt.wantWarning, tt.wantErr)
			}
		})
	}
}

func TestParseSPDXVersion(t *testing.T) {
	clearFlagEnv(t)
	if parsed, err := parse(nil); err != nil || parsed.cfg.SPDXVersion != "2" {
		t.Errorf("default spdx-version = %q, err %v; want 2", parsed.cfg.SPDXVersion, err)
	}
	writeConfig(t, ".go-sbom.yml", "spdx-version: 3\n")
	if parsed, err := parse(nil); err != nil || parsed.cfg.SPDXVersion != "3" {
		t.Errorf("spdx-version from config = %q, err %v; want 3", parsed.cfg.SPDXVersion, err)
	}
	if parsed, err := parse([]string{"--spdx-version", "2.3"}); err != nil || parsed.cfg.SPDXVersion != "2.3" {
		t.Errorf("--spdx-version should beat config: %q, err %v", parsed.cfg.SPDXVersion, err)
	}
}

func TestSplitList(t *testing.T) {
	got := SplitList([]string{"MIT, ISC", " BSD-3-Clause ", "", ","})
	if want := []string{"MIT", "ISC", "BSD-3-Clause"}; !slices.Equal(got, want) {
		t.Errorf("SplitList = %v, want %v", got, want)
	}
}

func TestSelectInput(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		env     map[string]string
		args    []string
		want    Config // only File, Image and ImageArchive are compared
		wantErr string
	}{
		{name: "nothing", wantErr: "nothing to analyze"},
		{name: "file from config", config: "file: go.mod\n", want: Config{File: "go.mod"}},
		{name: "image flag beats config file", config: "file: go.mod\n", args: []string{"--image", "alpine:3"}, want: Config{Image: "alpine:3"}},
		{name: "archive flag beats config file", config: "file: go.mod\n", args: []string{"--image-archive", "a.tar"}, want: Config{ImageArchive: "a.tar"}},
		{name: "positional beats env image", env: map[string]string{"GO_SBOM_IMAGE": "alpine:3"}, args: []string{"go.mod"}, want: Config{File: "go.mod"}},
		{name: "env image beats config file", config: "file: go.mod\n", env: map[string]string{"GO_SBOM_IMAGE": "alpine:3"}, want: Config{Image: "alpine:3"}},
		{name: "two on the command line", args: []string{"go.mod", "--image", "alpine:3"}, wantErr: "--file and --image are mutually exclusive"},
		{name: "two flags", args: []string{"--image", "alpine:3", "--image-archive", "a.tar"}, wantErr: "--image and --image-archive are mutually exclusive"},
		{name: "two in env", env: map[string]string{"GO_SBOM_FILE": "go.mod", "GO_SBOM_IMAGE_ARCHIVE": "a.tar"}, wantErr: "mutually exclusive"},
		{name: "two in config", config: "file: go.mod\nimage: alpine:3\n", wantErr: "mutually exclusive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearFlagEnv(t)
			if tt.config != "" {
				writeConfig(t, ".go-sbom.yml", tt.config)
			}
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			parsed, err := parse(tt.args)
			if err != nil {
				t.Fatal(err)
			}
			cfg := parsed.cfg
			if err := resolveFile(&cfg, parsed.positional, parsed.cliFile); err != nil {
				t.Fatal(err)
			}
			err = selectInput(&cfg, parsed.cliInputs, parsed.envInputs)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := Config{File: cfg.File, Image: cfg.Image, ImageArchive: cfg.ImageArchive}
			if got.File != tt.want.File || got.Image != tt.want.Image || got.ImageArchive != tt.want.ImageArchive {
				t.Errorf("input = file %q image %q archive %q; want %q %q %q",
					got.File, got.Image, got.ImageArchive, tt.want.File, tt.want.Image, tt.want.ImageArchive)
			}
		})
	}
}

func TestParseImageFlags(t *testing.T) {
	clearFlagEnv(t)
	parsed, err := parse([]string{"--image", "alpine:3", "--platform", "linux/arm64"})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.cfg.ImageTimeout != 10*time.Minute || parsed.cfg.Platform != "linux/arm64" {
		t.Errorf("ImageTimeout %v, Platform %q; want 10m and linux/arm64", parsed.cfg.ImageTimeout, parsed.cfg.Platform)
	}
	writeConfig(t, ".go-sbom.yml", "image-timeout: 30s\n")
	if parsed, err := parse(nil); err != nil || parsed.cfg.ImageTimeout != 30*time.Second {
		t.Errorf("image-timeout from config = %v, err %v; want 30s", parsed.cfg.ImageTimeout, err)
	}
}
