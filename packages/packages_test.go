package packages

import (
	"debug/buildinfo"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
)

func TestReadGoMod(t *testing.T) {
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")

	content := `module github.com/example/testmod

go 1.22.0

require (
	github.com/google/uuid v1.6.0
	github.com/pkg/errors v0.9.1
	golang.org/x/net v0.21.0
)
`
	if err := os.WriteFile(gomod, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := Read(gomod)
	if err != nil {
		t.Fatal(err)
	}

	if info.GoVersion != "1.22.0" {
		t.Errorf("GoVersion = %q, want %q", info.GoVersion, "1.22.0")
	}
	if info.Path != "github.com/example/testmod" {
		t.Errorf("Path = %q, want %q", info.Path, "github.com/example/testmod")
	}
	if info.Main.Path != "github.com/example/testmod" {
		t.Errorf("Main.Path = %q, want %q", info.Main.Path, "github.com/example/testmod")
	}
	if info.Dir != dir {
		t.Errorf("Dir = %q, want %q", info.Dir, dir)
	}
	if len(info.Deps) != 3 {
		t.Fatalf("len(Deps) = %d, want 3", len(info.Deps))
	}

	deps := make(map[string]Package)
	for _, d := range info.Deps {
		deps[d.Path] = d
	}

	uuid, ok := deps["github.com/google/uuid"]
	if !ok {
		t.Fatal("missing dep github.com/google/uuid")
	}
	if uuid.Version != "v1.6.0" {
		t.Errorf("uuid version = %q, want %q", uuid.Version, "v1.6.0")
	}
}

func TestReadGoModWithReplace(t *testing.T) {
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")

	content := `module github.com/example/testmod

go 1.22.0

require (
	github.com/old/pkg v1.0.0
	github.com/simple/dep v0.5.0
)

replace github.com/old/pkg => github.com/new/pkg v2.0.0
`
	if err := os.WriteFile(gomod, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := Read(gomod)
	if err != nil {
		t.Fatal(err)
	}

	if len(info.Deps) != 2 {
		t.Fatalf("len(Deps) = %d, want 2", len(info.Deps))
	}

	deps := make(map[string]Package)
	for _, d := range info.Deps {
		deps[d.Path] = d
	}

	old := deps["github.com/old/pkg"]
	if old.Replace == nil {
		t.Fatal("old/pkg should have a Replace")
	}
	if old.Replace.Path != "github.com/new/pkg" {
		t.Errorf("Replace.Path = %q, want %q", old.Replace.Path, "github.com/new/pkg")
	}
	if old.Replace.Version != "v2.0.0" {
		t.Errorf("Replace.Version = %q, want %q", old.Replace.Version, "v2.0.0")
	}

	simple := deps["github.com/simple/dep"]
	if simple.Replace != nil {
		t.Error("simple/dep should not have a Replace")
	}
}

func TestReadGoModNoGoVersion(t *testing.T) {
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")

	content := `module github.com/example/testmod

require github.com/google/uuid v1.6.0
`
	if err := os.WriteFile(gomod, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := Read(gomod)
	if err != nil {
		t.Fatal(err)
	}

	if info.GoVersion != "" {
		t.Errorf("GoVersion should be empty, got %q", info.GoVersion)
	}
}

func TestReadGoModNoDeps(t *testing.T) {
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")

	content := `module github.com/example/empty

go 1.22.0
`
	if err := os.WriteFile(gomod, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := Read(gomod)
	if err != nil {
		t.Fatal(err)
	}

	if len(info.Deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(info.Deps))
	}
}

func TestReadGoModInvalid(t *testing.T) {
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")

	if err := os.WriteFile(gomod, []byte("this is not a valid go.mod"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Read(gomod)
	if err == nil {
		t.Fatal("expected error for invalid go.mod")
	}
}

func TestReadNonExistentFile(t *testing.T) {
	_, err := Read("/nonexistent/path/to/file")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestReadGoModMultipleReplaces(t *testing.T) {
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")

	content := `module github.com/example/testmod

go 1.22.0

require (
	github.com/a/pkg v1.0.0
	github.com/b/pkg v1.0.0
	github.com/c/pkg v1.0.0
)

replace (
	github.com/a/pkg => github.com/a/fork v1.1.0
	github.com/b/pkg => github.com/b/fork v2.0.0
)
`
	if err := os.WriteFile(gomod, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := Read(gomod)
	if err != nil {
		t.Fatal(err)
	}

	deps := make(map[string]Package)
	for _, d := range info.Deps {
		deps[d.Path] = d
	}

	if deps["github.com/a/pkg"].Replace == nil {
		t.Error("a/pkg should have Replace")
	}
	if deps["github.com/b/pkg"].Replace == nil {
		t.Error("b/pkg should have Replace")
	}
	if deps["github.com/c/pkg"].Replace != nil {
		t.Error("c/pkg should not have Replace")
	}
}

func TestReadDispatchesByFilename(t *testing.T) {
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")

	content := `module github.com/example/testmod

go 1.22.0
`
	if err := os.WriteFile(gomod, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	// Should dispatch to readGoMod
	info, err := Read(gomod)
	if err != nil {
		t.Fatal(err)
	}
	if info.Path != "github.com/example/testmod" {
		t.Error("Read did not dispatch to readGoMod correctly")
	}
}

func TestReadBinaryInvalidFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "notabinary")

	if err := os.WriteFile(file, []byte("not a go binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Read(file)
	if err == nil {
		t.Fatal("expected error for non-binary file")
	}
}

func TestEffective(t *testing.T) {
	p := Package{Path: "a"}
	if p.Effective() != &p {
		t.Error("Effective without Replace should return the package itself")
	}
	r := Package{Path: "a", Replace: &Package{Path: "b"}}
	r.Effective().License = "MIT"
	if r.Replace.License != "MIT" {
		t.Error("Effective with Replace should return the replacement")
	}
}

func TestIsLocal(t *testing.T) {
	for path, want := range map[string]bool{
		"./fork": true, "../fork": true, "/abs/fork": true,
		"github.com/a/b": false, "": false,
	} {
		p := Package{Path: path}
		if got := p.IsLocal(); got != want {
			t.Errorf("IsLocal(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestPackageRef(t *testing.T) {
	tests := map[string]Package{
		"example.com/a@v1.0.0": {Path: "example.com/a", Version: "v1.0.0"},
		"example.com/app":      {Path: "example.com/app"},
		"../fork":              {Path: "../fork"},
	}
	for want, pkg := range tests {
		if got := pkg.Ref(); got != want {
			t.Errorf("Ref() = %q, want %q", got, want)
		}
	}
}

func TestReadBinarySelf(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	info, err := Read(exe)
	if err != nil {
		t.Fatal(err)
	}
	if info.Main.Path != "github.com/oktalz/go-sbom" || info.Dir != filepath.Dir(exe) || info.GoVersion == "" {
		t.Errorf("Main.Path %q, Dir %q, GoVersion %q", info.Main.Path, info.Dir, info.GoVersion)
	}
	if len(info.Deps) == 0 {
		t.Error("no dependencies read from the test binary")
	}
}

func TestFromBuildInfo(t *testing.T) {
	bi := &buildinfo.BuildInfo{
		GoVersion: "go1.27.0",
		Path:      "example.com/app/cmd",
		Main:      debug.Module{Path: "example.com/app", Version: "v1.0.0", Sum: "h1:main"},
		Deps: []*debug.Module{
			{Path: "example.com/a", Version: "v1.0.0", Sum: "h1:a"},
			{Path: "example.com/b", Version: "v1.0.0", Replace: &debug.Module{Path: "example.com/fork", Version: "v1.1.0", Sum: "h1:f"}},
		},
		Settings: []debug.BuildSetting{{Key: "CGO_ENABLED", Value: "1"}},
	}
	info := FromBuildInfo(bi)
	if info.Dir != "" || !info.CGOEnabled || info.GoVersion != "go1.27.0" || info.Path != "example.com/app/cmd" {
		t.Errorf("info = %+v", info)
	}
	if info.Main != (Package{Path: "example.com/app", Version: "v1.0.0", Sum: "h1:main"}) {
		t.Errorf("Main = %+v", info.Main)
	}
	if len(info.Deps) != 2 || info.Deps[1].Replace == nil || info.Deps[1].Effective().Ref() != "example.com/fork@v1.1.0" {
		t.Errorf("Deps = %+v", info.Deps)
	}
}
