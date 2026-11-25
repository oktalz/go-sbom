package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	tmpDir, err := os.MkdirTemp("", "go-sbom-doc-")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Build the binary
	bin := filepath.Join(tmpDir, "go-sbom")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		return fmt.Errorf("build failed: %w", err)
	}

	// Run -h to capture usage output (-h exits 0, output goes to stdout)
	out, err := exec.Command(bin, "-h").CombinedOutput()
	if err != nil {
		return fmt.Errorf("running %s -h: %w\n%s", bin, err, out)
	}
	usage := strings.TrimRight(string(out), "\n ")

	readme, err := os.ReadFile("README.md")
	if err != nil {
		return fmt.Errorf("reading README.md: %w", err)
	}

	// Replace the usage code block after ### Usage
	re := regexp.MustCompile("(?s)(### Usage\n\n```\n).*?(```)")
	if !re.Match(readme) {
		return errors.New("README.md has no \"### Usage\" code block")
	}
	// A func replacement keeps any '$' in the usage text literal.
	updated := re.ReplaceAllStringFunc(string(readme), func(block string) string {
		m := re.FindStringSubmatch(block)
		return m[1] + usage + "\n" + m[2]
	})

	if updated == string(readme) {
		fmt.Println("README.md is up to date")
		return nil
	}

	if err := os.WriteFile("README.md", []byte(updated), 0o644); err != nil {
		return fmt.Errorf("writing README.md: %w", err)
	}
	fmt.Println("README.md updated")
	return nil
}
