// Command test-image packs a fixture filesystem and a binary into a docker save tarball.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/oktalz/go-sbom/internal/testimage"
)

func main() {
	root := flag.String("root", "", "directory with the image filesystem")
	binary := flag.String("binary", "", "binary to add as /usr/bin/<name>")
	tag := flag.String("tag", "go-sbom-test/image:1", "image tag recorded in the tarball")
	out := flag.String("o", "", "output tarball")
	flag.Parse()
	if *root == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: test-image -root DIR [-binary FILE] [-tag TAG] -o FILE")
		os.Exit(1)
	}
	if err := run(*root, *binary, *tag, *out); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(root, binary, tag, out string) error {
	files, err := testimage.DirFiles(root)
	if err != nil {
		return err
	}
	if binary != "" {
		data, err := os.ReadFile(binary)
		if err != nil {
			return err
		}
		files["/usr/bin/"+filepath.Base(binary)] = data
	}
	layer, err := testimage.Layer(files)
	if err != nil {
		return err
	}
	img, err := testimage.Image("linux/amd64", layer)
	if err != nil {
		return err
	}
	t, err := name.NewTag(tag)
	if err != nil {
		return err
	}
	return tarball.WriteToFile(out, t, img)
}
