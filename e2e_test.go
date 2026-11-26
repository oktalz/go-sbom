package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/oktalz/go-sbom/internal/testimage"
)

// e2eEnv makes the test binary run main() instead of the tests.
const e2eEnv = "GOSBOM_E2E_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(e2eEnv) == "1" {
		main()
		os.Exit(0)
	}
	m.Run()
}

// runCLI runs go-sbom with args in dir and returns stdout, stderr and the exit code.
func runCLI(t *testing.T, dir string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), e2eEnv+"=1", "GOPROXY=off", "GOFLAGS=-mod=mod")
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err = cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	case err != nil:
		t.Fatal(err)
	}
	return out.String(), errOut.String(), code
}

// alpineArchive writes the alpine fixture as a docker save tarball in dir.
func alpineArchive(t *testing.T, dir string) string {
	t.Helper()
	files, err := testimage.DirFiles("testdata/sbom/image-alpine")
	if err != nil {
		t.Fatal(err)
	}
	layer, err := testimage.Layer(files)
	if err != nil {
		t.Fatal(err)
	}
	img, err := testimage.Image("linux/amd64", layer)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "alpine.tar")
	if err := tarball.WriteToFile(file, name.MustParseReference("go-sbom-test/alpine:3.20").(name.Tag), img); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestCLI(t *testing.T) {
	for _, k := range []string{"GO_SBOM_FILE", "GO_SBOM_IMAGE", "GO_SBOM_IMAGE_ARCHIVE", "GO_SBOM_ALLOWED", "GO_SBOM_CHECK", "GO_SBOM_CONFIG"} {
		t.Setenv(k, "")
		_ = os.Unsetenv(k)
	}
	dir := t.TempDir() // no .go-sbom.yml
	archive := alpineArchive(t, dir)
	nodeps, err := filepath.Abs("testdata/sbom/nodeps/go.mod")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout []string
		wantStderr []string
	}{
		{name: "nothing to analyze", wantCode: 1, wantStderr: []string{"nothing to analyze"}},
		{name: "file and image", args: []string{nodeps, "--image", "alpine"}, wantCode: 1, wantStderr: []string{"mutually exclusive"}},
		{name: "missing file", args: []string{"missing/go.mod"}, wantCode: 1, wantStderr: []string{"error:"}},
		{name: "bad format", args: []string{nodeps, "--format", "xml"}, wantCode: 1, wantStderr: []string{"invalid --format"}},
		{name: "check without allowed", args: []string{nodeps, "--check"}, wantCode: 1, wantStderr: []string{"--check needs allowed licenses"}},
		{name: "go.mod text", args: []string{nodeps}, wantStdout: []string{"Module:", "PACKAGE"}},
		{
			name: "image csv", args: []string{"--image-archive", archive, "--format", "csv"},
			wantStdout: []string{"package,version,license,type", "musl,1.2.5-r0,MIT,apk", "busybox,1.36.1-r29,GPL-2.0-only,apk"},
		},
		{
			name: "image cyclonedx", args: []string{"--image-archive", archive, "--format", "cyclonedx"},
			wantStdout: []string{`"type": "container"`, "pkg:apk/alpine/musl@1.2.5-r0?arch=x86_64\u0026distro=alpine-3.20.3"},
		},
		{
			name: "image check fails", args: []string{"--image-archive", archive, "--check", "--allowed", "MIT,MPL-2.0"},
			wantCode: 2, wantStderr: []string{"busybox@1.36.1-r29: GPL-2.0-only"},
		},
		{name: "image check passes", args: []string{"--image-archive", archive, "--check", "--allowed", "MIT,MPL-2.0,GPL-2.0-only"}},
		{name: "image check with exclude", args: []string{"--image-archive", archive, "--check", "--allowed", "MIT,MPL-2.0", "--exclude", "busybox"}},
		{name: "image check with licence", args: []string{"--image-archive", archive, "--check", "--allowed", "MIT,MPL-2.0", "--licence", "busybox:MIT"}},
		{name: "missing archive", args: []string{"--image-archive", filepath.Join(dir, "none.tar")}, wantCode: 1, wantStderr: []string{"reading image archive"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, code := runCLI(t, dir, tt.args...)
			if code != tt.wantCode {
				t.Fatalf("exit code %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, stdout, stderr)
			}
			for _, want := range tt.wantStdout {
				if !strings.Contains(stdout, want) {
					t.Errorf("stdout missing %q:\n%s", want, stdout)
				}
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr missing %q:\n%s", want, stderr)
				}
			}
		})
	}
}

func TestCLIImageOutputFile(t *testing.T) {
	dir := t.TempDir()
	archive := alpineArchive(t, dir)
	if err := os.WriteFile(filepath.Join(dir, ".go-sbom.yml"), []byte("file: go.mod\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// --image-archive on the command line beats file: in the config file.
	if _, stderr, code := runCLI(t, dir, "--image-archive", archive, "-o", "sbom.spdx3.json"); code != 0 {
		t.Fatalf("exit code %d\n%s", code, stderr)
	}
	data, err := os.ReadFile(filepath.Join(dir, "sbom.spdx3.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"software_primaryPurpose": "container"`) {
		t.Errorf("SPDX 3 output has no container package:\n%s", data)
	}
}
