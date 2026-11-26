package image

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	_ "github.com/glebarez/go-sqlite" // the "sqlite" driver go-rpmdb opens
	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	"github.com/oktalz/go-sbom/packages"
)

// rpmDirs and rpmDBs list where rpm keeps its database, in lookup order.
var (
	rpmDirs = []string{"/usr/lib/sysimage/rpm", "/var/lib/rpm", "/usr/share/rpm"}
	rpmDBs  = []string{"rpmdb.sqlite", "Packages.db", "Packages"} // SQLite, NDB, BerkeleyDB
)

// isRPMFile reports whether p is an rpm database file, or the WAL of a SQLite one.
// shortcut: a database behind a file-level link is missed; follow links if images need it.
func isRPMFile(p string) bool {
	dir, file := path.Split(p)
	return slices.Contains(rpmDirs, strings.TrimSuffix(dir, "/")) &&
		(slices.Contains(rpmDBs, file) || file == "rpmdb.sqlite-wal")
}

// saveRPM streams an rpm database to a temp file: go-rpmdb opens databases by path.
func (s *scan) saveRPM(r io.Reader, p string, size int64) error {
	if size > maxBinarySize {
		return fmt.Errorf("rpm database %s is larger than %d MiB", p, maxBinarySize>>20)
	}
	if s.tmp == "" {
		dir, err := os.MkdirTemp("", "go-sbom-rpm-")
		if err != nil {
			return err
		}
		s.tmp = dir
	}
	// One subdirectory per image directory keeps a SQLite file next to its WAL.
	sub := filepath.Join(s.tmp, strconv.Itoa(slices.Index(rpmDirs, path.Dir(p))))
	if err := os.MkdirAll(sub, 0o700); err != nil {
		return err
	}
	file := filepath.Join(sub, path.Base(p))
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		return fmt.Errorf("reading %s: %w", p, err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	s.rpm[p] = file
	return nil
}

// rpmPackages lists the packages of the first rpm database found.
// Older databases left by a migration are ignored: they would list stale versions.
func (s *scan) rpmPackages() ([]packages.Package, bool, error) {
	for _, dir := range rpmDirs {
		for _, name := range rpmDBs {
			p := dir + "/" + name
			if file, ok := s.rpm[p]; ok {
				pkgs, err := readRPM(file)
				if err != nil {
					return nil, true, fmt.Errorf("reading rpm database %s: %w", p, err)
				}
				return pkgs, true, nil
			}
		}
	}
	return nil, false, nil
}

func readRPM(file string) ([]packages.Package, error) {
	db, err := rpmdb.Open(file)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	list, err := db.ListPackages()
	if err != nil {
		return nil, err
	}
	var out []packages.Package
	for _, p := range list {
		if p.Name == "gpg-pubkey" {
			continue // an imported signing key, not a package
		}
		version := p.Version + "-" + p.Release
		if p.Epoch != nil && *p.Epoch != 0 {
			version = strconv.Itoa(*p.Epoch) + ":" + version
		}
		out = append(out, packages.Package{
			Type:    packages.TypeRPM,
			Path:    p.Name,
			Version: version,
			Arch:    p.Arch,
			License: rpmLicense(p.License),
		})
	}
	return out, nil
}

// rpmLicense maps old Fedora license names ("GPLv2+ and ASL 2.0") to SPDX where unambiguous.
func rpmLicense(l string) string {
	return licenseTokens(strings.ReplaceAll(l, "ASL 2.0", "Apache-2.0"))
}

func (s *scan) close() {
	if s.tmp != "" {
		_ = os.RemoveAll(s.tmp)
	}
}
