package image

import (
	"archive/tar"
	"bytes"
	"debug/buildinfo"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/oktalz/go-sbom/packages"
)

const (
	// maxBinarySize bounds memory: each ELF file is read whole for buildinfo.
	maxBinarySize = 512 << 20
	maxDataSize   = 32 << 20
)

// Paths of the files the OS package parsers read.
const (
	osRelease    = "/etc/os-release"
	osReleaseUsr = "/usr/lib/os-release"
	apkDB        = "/lib/apk/db/installed"
	apkDBUsr     = "/usr/lib/apk/db/installed" // usr-merged layout
	dpkgStatus   = "/var/lib/dpkg/status"
	dpkgStatusD  = "/var/lib/dpkg/status.d/"
	docDir       = "/usr/share/doc/"
)

var elfMagic = []byte("\x7fELF")

type binary struct {
	bi   *buildinfo.BuildInfo
	path string
}

// scan holds what one pass over the image filesystem found.
type scan struct {
	files    map[string][]byte // package DB, os-release and copyright files
	links    map[string]string // link path -> target, for wanted paths and doc directories
	rpm      map[string]string // rpm database image path -> temp file
	tmp      string            // temp directory of the rpm databases
	buf      []byte            // reused for ELF files
	binaries []binary
}

// walk reads the image filesystem once. The caller closes the returned scan.
func walk(r io.Reader, verbose bool) (*scan, error) {
	s := &scan{files: map[string][]byte{}, links: map[string]string{}, rpm: map[string]string{}}
	if err := s.walk(r, verbose); err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

func (s *scan) walk(r io.Reader, verbose bool) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		p := path.Clean("/" + hdr.Name)
		switch hdr.Typeflag {
		case tar.TypeReg:
		case tar.TypeLink, tar.TypeSymlink:
			s.link(p, hdr)
			continue
		default:
			continue
		}
		if isRPMFile(p) {
			if err := s.saveRPM(tr, p, hdr.Size); err != nil {
				return err
			}
			continue
		}
		if wanted(p) {
			if hdr.Size > maxDataSize {
				fmt.Fprintf(os.Stderr, "warning: skipping %s: larger than %d MiB\n", p, maxDataSize>>20)
				continue
			}
			data, err := io.ReadAll(tr)
			if err != nil {
				return fmt.Errorf("reading %s: %w", p, err)
			}
			s.files[p] = data
			continue
		}
		if err := s.binary(tr, p, hdr.Size, verbose); err != nil {
			return err
		}
	}
}

// link records a link that a parser may need to follow, e.g. a shared doc directory.
func (s *scan) link(p string, hdr *tar.Header) {
	if !wanted(p) && !isDocDir(p) {
		return
	}
	target := hdr.Linkname
	switch {
	case hdr.Typeflag == tar.TypeLink, strings.HasPrefix(target, "/"):
		target = path.Clean("/" + target) // hard link names are archive paths
	default:
		target = path.Join(path.Dir(p), target)
	}
	s.links[p] = target
}

// read returns the file at p, following recorded links of p or its directory.
func (s *scan) read(p string) []byte {
	for range 8 { // bounds link loops
		if data, ok := s.files[p]; ok {
			return data
		}
		if t, ok := s.links[p]; ok {
			p = t
			continue
		}
		dir, file := path.Split(p)
		t, ok := s.links[strings.TrimSuffix(dir, "/")]
		if !ok {
			return nil
		}
		p = path.Join(t, file)
	}
	return nil
}

func isDocDir(p string) bool {
	pkg, ok := strings.CutPrefix(p, docDir)
	return ok && pkg != "" && !strings.Contains(pkg, "/")
}

// binary records the file at p when it is a Go binary.
func (s *scan) binary(r io.Reader, p string, size int64, verbose bool) error {
	if size < int64(len(elfMagic)) {
		return nil
	}
	magic := make([]byte, len(elfMagic))
	if _, err := io.ReadFull(r, magic); err != nil {
		return fmt.Errorf("reading %s: %w", p, err)
	}
	if !bytes.Equal(magic, elfMagic) {
		return nil
	}
	if size > maxBinarySize {
		fmt.Fprintf(os.Stderr, "warning: skipping %s: larger than %d MiB\n", p, maxBinarySize>>20)
		return nil
	}
	if int64(cap(s.buf)) < size {
		s.buf = make([]byte, size)
	}
	buf := s.buf[:size]
	copy(buf, magic)
	if _, err := io.ReadFull(r, buf[len(magic):]); err != nil {
		return fmt.Errorf("reading %s: %w", p, err)
	}
	bi, err := buildinfo.Read(bytes.NewReader(buf))
	if err != nil {
		return nil // not a Go binary, or one without build info
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "[verbose] found Go binary %s (%s)\n", p, bi.Path)
	}
	s.binaries = append(s.binaries, binary{path: p, bi: bi})
	return nil
}

// wanted reports whether the file at p is read by an OS package parser.
func wanted(p string) bool {
	switch p {
	case osRelease, osReleaseUsr, apkDB, apkDBUsr, dpkgStatus:
		return true
	}
	if file, ok := strings.CutPrefix(p, dpkgStatusD); ok {
		return !strings.Contains(file, "/") && !strings.HasSuffix(file, ".md5sums")
	}
	if rest, ok := strings.CutPrefix(p, docDir); ok {
		pkg, file, _ := strings.Cut(rest, "/")
		return pkg != "" && file == "copyright"
	}
	return false
}

// info turns the scan into packages: every Go module once, then OS packages.
func (s *scan) info() (*packages.Info, error) {
	info := &packages.Info{Image: &packages.ImageInfo{}}
	seen := map[string]bool{}
	add := func(p packages.Package) {
		key := p.Type + " " + p.Ref() + " " + p.Arch
		if p.Replace != nil {
			key += " => " + p.Replace.Ref()
		}
		if !seen[key] {
			seen[key] = true
			info.Deps = append(info.Deps, p)
		}
	}

	for _, b := range s.binaries {
		bi := packages.FromBuildInfo(b.bi)
		info.Image.Binaries = append(info.Image.Binaries, b.path)
		if bi.CGOEnabled {
			info.CGOEnabled = true
			info.Image.CGOBinaries = append(info.Image.CGOBinaries, b.path)
		}
		if bi.Main.Path != "" {
			m := bi.Main
			m.License = "Unknown" // as for a binary: never sent to a proxy, often private
			add(m)
		}
		for _, d := range bi.Deps {
			add(d)
		}
	}

	id, distro := parseOSRelease(s.osRelease())
	info.Image.Distro = distro
	pkgs, found, err := s.osPackages()
	if err != nil {
		return nil, err
	}
	if !found && id != "" {
		fmt.Fprintf(os.Stderr, "warning: no package database found in the %s image; OS packages are not listed\n", distro)
	}
	for _, p := range pkgs {
		p.Namespace, p.Distro = id, distro
		add(p)
	}
	return info, nil
}

func (s *scan) osRelease() []byte {
	if data := s.read(osRelease); data != nil {
		return data
	}
	return s.read(osReleaseUsr)
}
