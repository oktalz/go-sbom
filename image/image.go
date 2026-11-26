package image

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/oktalz/go-sbom/packages"
)

// Options configures [Read].
type Options struct {
	// Platform selects the image of a multi-platform index ("" means linux/<GOARCH>).
	Platform string
	Verbose  bool
}

// Read lists the Go modules and OS packages of a container image, taken from
// a registry (ref) or from a docker save tarball (archive).
func Read(ctx context.Context, ref, archive string, opts Options) (*packages.Info, error) {
	var (
		img     v1.Image
		src     source
		openErr error
	)
	if archive != "" {
		img, src, openErr = openArchive(archive)
	} else {
		img, src, openErr = openRemote(ctx, ref, opts.Platform)
	}
	if openErr != nil {
		return nil, openErr
	}

	digest, err := img.Digest()
	if archive != "" {
		// The manifest of a docker save tarball is rebuilt by ggcr; the image ID is stable.
		digest, err = img.ConfigName()
	}
	if err != nil {
		return nil, fmt.Errorf("reading image digest: %w", err)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("reading image config: %w", err)
	}
	if err := checkPlatform(cfg.Platform(), opts.Platform); err != nil {
		return nil, err
	}

	fs := mutate.Extract(img)
	defer fs.Close()
	s, err := walk(fs, opts.Verbose)
	if err != nil {
		return nil, fmt.Errorf("reading image filesystem: %w", err)
	}
	defer s.close()

	info, err := s.info()
	if err != nil {
		return nil, err
	}
	info.Main = packages.Package{Type: packages.TypeOCI, Path: src.repo, Version: digest.String(), Arch: cfg.Architecture}
	info.Image.Ref = src.ref
	info.Image.Digest = digest.String()
	info.Image.Platform = cfg.Platform().String()
	return info, nil
}

// checkPlatform fails when a requested platform does not match the image.
// A single-platform image is returned whatever the requested platform.
func checkPlatform(got *v1.Platform, want string) error {
	if want == "" {
		return nil
	}
	p, err := v1.ParsePlatform(want)
	if err != nil {
		return fmt.Errorf("invalid platform %q: %w", want, err)
	}
	if got == nil {
		return fmt.Errorf("image has no platform, not %s", want)
	}
	if !got.Satisfies(*p) {
		return fmt.Errorf("image is for %s, not %s", got, want)
	}
	return nil
}

// source names the image: ref as given, repo as its full repository name.
type source struct {
	ref  string
	repo string
}

func openArchive(archive string) (v1.Image, source, error) {
	src := source{ref: archive, repo: filepath.Base(archive)}
	manifest, err := tarball.LoadManifest(func() (io.ReadCloser, error) { return os.Open(archive) })
	if err != nil {
		return nil, src, fmt.Errorf("reading image archive %s: %w", archive, err)
	}
	if len(manifest) == 1 && len(manifest[0].RepoTags) > 0 {
		if tag, err := name.NewTag(manifest[0].RepoTags[0]); err == nil {
			src = source{ref: tag.String(), repo: tag.Context().Name()}
		}
	}
	img, err := tarball.ImageFromPath(archive, nil)
	if err != nil {
		return nil, src, fmt.Errorf("reading image archive %s: %w", archive, err)
	}
	return img, src, nil
}

func openRemote(ctx context.Context, ref, platform string) (v1.Image, source, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, source{}, fmt.Errorf("invalid image reference %q: %w", ref, err)
	}
	src := source{ref: ref, repo: r.Context().Name()}
	if platform == "" {
		platform = "linux/" + runtime.GOARCH
	}
	p, err := v1.ParsePlatform(platform)
	if err != nil {
		return nil, src, fmt.Errorf("invalid platform %q: %w", platform, err)
	}

	opts := []remote.Option{remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain)}
	img, err := remote.Image(r, append(opts, remote.WithPlatform(*p))...)
	if err == nil {
		return img, src, nil
	}
	if available := indexPlatforms(r, opts); len(available) > 0 {
		return nil, src, fmt.Errorf("pulling %s for %s: %w (available platforms: %s)", ref, platform, err, strings.Join(available, ", "))
	}
	var terr *transport.Error
	if errors.As(err, &terr) && terr.StatusCode == http.StatusUnauthorized {
		return nil, src, fmt.Errorf("pulling %s: %w (log in with docker login)", ref, err)
	}
	return nil, src, fmt.Errorf("pulling %s: %w", ref, err)
}

// indexPlatforms lists the platforms of a multi-platform image, or nil.
func indexPlatforms(r name.Reference, opts []remote.Option) []string {
	idx, err := remote.Index(r, opts...)
	if err != nil {
		return nil
	}
	m, err := idx.IndexManifest()
	if err != nil {
		return nil
	}
	var out []string
	for _, d := range m.Manifests {
		if d.Platform != nil && d.Platform.OS != "unknown" { // unknown/unknown are attestations
			out = append(out, d.Platform.String())
		}
	}
	return out
}
