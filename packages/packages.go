package packages

import (
	"debug/buildinfo"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/mod/modfile"
)

type Package struct {
	Path        string
	Version     string
	Sum         string
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
	GoVersion  string
	Path       string
	Dir        string // project directory (set when reading go.mod)
	Main       Package
	Deps       []Package
	CGOEnabled bool // true when binary was built with CGO_ENABLED=1
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
		Dir:        filepath.Dir(file),
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

	return info, nil
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
