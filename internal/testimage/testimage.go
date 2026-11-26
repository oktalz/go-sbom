// Package testimage builds small container images for tests and SBOM fixtures.
package testimage

import (
	"archive/tar"
	"bytes"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// Layer builds a layer from image paths and contents. A nil content is a whiteout.
func Layer(files map[string][]byte) (v1.Layer, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range slices.Sorted(maps.Keys(files)) {
		data := files[name]
		hdrName := strings.TrimPrefix(name, "/")
		if data == nil {
			dir, base := path.Split(hdrName)
			hdrName = dir + ".wh." + base
		}
		hdr := &tar.Header{Name: hdrName, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	b := buf.Bytes()
	return tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(b)), nil
	})
}

// Image stacks layers into an image for platform (e.g. "linux/amd64").
func Image(platform string, layers ...v1.Layer) (v1.Image, error) {
	p, err := v1.ParsePlatform(platform)
	if err != nil {
		return nil, err
	}
	img, err := mutate.AppendLayers(empty.Image, layers...)
	if err != nil {
		return nil, err
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}
	cfg = cfg.DeepCopy()
	cfg.OS, cfg.Architecture, cfg.Variant = p.OS, p.Architecture, p.Variant
	return mutate.ConfigFile(img, cfg)
}

// DirFiles reads the regular files below root, keyed by their image path.
func DirFiles(root string) (map[string][]byte, error) {
	files := map[string][]byte{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		files["/"+filepath.ToSlash(rel)] = data
		return nil
	})
	return files, err
}
