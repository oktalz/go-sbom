package packages

import (
	"debug/buildinfo"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/mod/modfile"
)

// Package types other than Go modules, named after their purl type.
const (
	TypeAPK = "apk"
	TypeDeb = "deb"
	TypeRPM = "rpm"
	TypeOCI = "oci" // a container image, only used for Info.Main
)

type Package struct {
	Path        string
	Version     string
	Sum         string
	Type        string // "" for a Go module
	Namespace   string // distro ID of an OS package (purl namespace)
	Distro      string // distro ID and version of an OS package (purl distro qualifier)
	Arch        string
	Replace     *Package
	License     string
	LicenseLink string
}

// Ref returns "path@version", or just the path when the version is empty
// (the main module of a go.mod, local directory replacements).
func (p *Package) Ref() string {
	if p.Version == "" {
		return p.Path
	}
	return p.Path + "@" + p.Version
}

// Effective returns the package that is actually built: the replacement when
// Replace is set, otherwise p itself. The returned pointer aliases p (or
// p.Replace), so writes through it update the original.
func (p *Package) Effective() *Package {
	if p.Replace != nil {
		return p.Replace
	}
	return p
}

// IsLocal reports whether the package refers to a directory on disk
// (a replace directive such as `=> ../fork`) rather than a module version.
func (p *Package) IsLocal() bool {
	return modfile.IsDirectoryPath(p.Path)
}

type Info struct {
	Image      *ImageInfo // set when a container image was analyzed
	Main       Package
	GoVersion  string
	Path       string
	Dir        string // project directory (set when reading go.mod)
	Deps       []Package
	CGOEnabled bool // true when binary was built with CGO_ENABLED=1
}

// ImageInfo describes an analyzed container image.
type ImageInfo struct {
	Ref         string
	Digest      string
	Platform    string
	Distro      string
	Binaries    []string // paths of the Go binaries in the image
	CGOBinaries []string
}

func Read(file string) (*Info, error) {
	if filepath.Base(file) == "go.mod" {
		return readGoMod(file)
	}
	return readBinary(file)
}

func readBinary(file string) (*Info, error) {
	bi, err := buildinfo.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("reading build info from %s: %w", file, err)
	}
	info := FromBuildInfo(bi)
	info.Dir = filepath.Dir(file)
	return info, nil
}

// FromBuildInfo maps the build info of a Go binary; Dir is left empty.
func FromBuildInfo(bi *buildinfo.BuildInfo) *Info {
	var cgoEnabled bool
	for _, s := range bi.Settings {
		if s.Key == "CGO_ENABLED" && s.Value == "1" {
			cgoEnabled = true
			break
		}
	}

	info := &Info{
		GoVersion:  bi.GoVersion,
		Path:       bi.Path,
		CGOEnabled: cgoEnabled,
		Main: Package{
			Path:    bi.Main.Path,
			Version: bi.Main.Version,
			Sum:     bi.Main.Sum,
		},
	}

	for _, dep := range bi.Deps {
		pkg := Package{
			Path:    dep.Path,
			Version: dep.Version,
			Sum:     dep.Sum,
		}
		if dep.Replace != nil {
			pkg.Replace = &Package{
				Path:    dep.Replace.Path,
				Version: dep.Replace.Version,
				Sum:     dep.Replace.Sum,
			}
		}
		info.Deps = append(info.Deps, pkg)
	}

	return info
}

func readGoMod(file string) (*Info, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", file, err)
	}

	mf, err := modfile.Parse(file, data, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", file, err)
	}

	info := &Info{
		Path: mf.Module.Mod.Path,
		Dir:  filepath.Dir(file),
		Main: Package{
			Path: mf.Module.Mod.Path,
		},
	}

	if mf.Go != nil {
		info.GoVersion = mf.Go.Version
	}

	replaces := make(map[string]*modfile.Replace)
	for _, r := range mf.Replace {
		replaces[r.Old.Path] = r
	}

	for _, req := range mf.Require {
		pkg := Package{
			Path:    req.Mod.Path,
			Version: req.Mod.Version,
		}
		if r, ok := replaces[req.Mod.Path]; ok {
			pkg.Replace = &Package{
				Path:    r.New.Path,
				Version: r.New.Version,
			}
		}
		info.Deps = append(info.Deps, pkg)
	}

	return info, nil
}
