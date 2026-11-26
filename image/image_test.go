package image

import (
	"archive/tar"
	"bytes"
	"context"
	"debug/buildinfo"
	"io"
	"log"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/oktalz/go-sbom/internal/testimage"
	"github.com/oktalz/go-sbom/packages"
)

const fixtures = "../testdata/sbom/"

// selfBinary is the test binary: a Go binary with build info.
func selfBinary(t *testing.T) []byte {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// fixtureImage builds an image from a testdata filesystem plus extra files.
func fixtureImage(t *testing.T, platform, dir string, extra map[string][]byte) v1.Image {
	t.Helper()
	files, err := testimage.DirFiles(fixtures + dir)
	if err != nil {
		t.Fatal(err)
	}
	maps.Copy(files, extra)
	layer, err := testimage.Layer(files)
	if err != nil {
		t.Fatal(err)
	}
	img, err := testimage.Image(platform, layer)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func writeArchive(t *testing.T, img v1.Image, tag string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "image.tar")
	ref, err := name.NewTag(tag)
	if err != nil {
		t.Fatal(err)
	}
	if err := tarball.WriteToFile(file, ref, img); err != nil {
		t.Fatal(err)
	}
	return file
}

// startRegistry runs an in-memory registry and returns its host:port.
func startRegistry(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func find(info *packages.Info, typ, path string) *packages.Package {
	for i := range info.Deps {
		if info.Deps[i].Type == typ && info.Deps[i].Path == path {
			return &info.Deps[i]
		}
	}
	return nil
}

func TestReadArchiveDebian(t *testing.T) {
	img := fixtureImage(t, "linux/amd64", "image-debian", map[string][]byte{
		"/usr/bin/app":       selfBinary(t),
		"/usr/lib/libnot.so": []byte("\x7fELF but not a Go binary"),
	})
	info, err := Read(context.Background(), "", writeArchive(t, img, "example.com/team/debian:12"), Options{})
	if err != nil {
		t.Fatal(err)
	}

	id, _ := img.ConfigName() // an archive is named by its image ID
	want := packages.Package{Type: packages.TypeOCI, Path: "example.com/team/debian", Version: id.String(), Arch: "amd64"}
	if info.Main != want {
		t.Errorf("Main = %+v, want %+v", info.Main, want)
	}
	img2 := info.Image
	if img2.Ref != "example.com/team/debian:12" || img2.Platform != "linux/amd64" || img2.Distro != "debian-12" {
		t.Errorf("Image = %+v", img2)
	}
	if !slices.Equal(img2.Binaries, []string{"/usr/bin/app"}) {
		t.Errorf("Binaries = %v, want [/usr/bin/app]", img2.Binaries)
	}

	if m := find(info, "", "github.com/oktalz/go-sbom"); m == nil {
		t.Error("main module of the Go binary is missing")
	}
	wantDeb := map[string]string{
		"libc6":      "LGPL-2.1-or-later", // the debian/* stanza is packaging
		"tzdata":     "public-domain",
		"base-files": "Unknown",
	}
	for pkg, license := range wantDeb {
		p := find(info, packages.TypeDeb, pkg)
		if p == nil {
			t.Errorf("deb %s missing", pkg)
			continue
		}
		if p.License != license || p.Namespace != "debian" || p.Distro != "debian-12" {
			t.Errorf("deb %s = %+v, want license %q in debian-12", pkg, p, license)
		}
	}
	if p := find(info, packages.TypeDeb, "removed-tool"); p != nil {
		t.Error("removed package is listed")
	}
	if p := find(info, packages.TypeDeb, "tzdata.md5sums"); p != nil {
		t.Error("md5sums file read as a package")
	}
}

func TestReadArchiveWithoutTag(t *testing.T) {
	img := fixtureImage(t, "linux/amd64", "image-alpine", nil)
	file := filepath.Join(t.TempDir(), "plain.tar")
	if err := tarball.Write(nil, img, mustCreate(t, file)); err != nil {
		t.Fatal(err)
	}
	info, err := Read(context.Background(), "", file, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if info.Main.Path != "plain.tar" || info.Image.Ref != file {
		t.Errorf("Main.Path = %q, Ref = %q; want plain.tar and the file", info.Main.Path, info.Image.Ref)
	}
}

func mustCreate(t *testing.T, file string) *os.File {
	t.Helper()
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestReadArchiveMissing(t *testing.T) {
	if _, err := Read(context.Background(), "", filepath.Join(t.TempDir(), "none.tar"), Options{}); err == nil {
		t.Fatal("expected an error for a missing archive")
	}
}

func TestReadRemoteAlpine(t *testing.T) {
	host := startRegistry(t)
	ref := host + "/alpine:3.20"
	r, _ := name.ParseReference(ref)
	img := fixtureImage(t, "linux/amd64", "image-alpine", nil)
	if err := remote.Write(r, img); err != nil {
		t.Fatal(err)
	}

	info, err := Read(context.Background(), ref, "", Options{Platform: "linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if digest, _ := img.Digest(); info.Main.Version != digest.String() {
		t.Errorf("Main.Version = %q, want the manifest digest %s", info.Main.Version, digest)
	}
	if info.Main.Path != host+"/alpine" || info.Image.Distro != "alpine-3.20.3" {
		t.Errorf("Main.Path = %q, Distro = %q", info.Main.Path, info.Image.Distro)
	}
	want := []packages.Package{
		{Type: packages.TypeAPK, Path: "musl", Version: "1.2.5-r0", Arch: "x86_64", License: "MIT", Namespace: "alpine", Distro: "alpine-3.20.3"},
		{Type: packages.TypeAPK, Path: "busybox", Version: "1.36.1-r29", Arch: "x86_64", License: "GPL-2.0-only", Namespace: "alpine", Distro: "alpine-3.20.3"},
		{Type: packages.TypeAPK, Path: "ca-certificates-bundle", Version: "20240705-r0", Arch: "x86_64", License: "MPL-2.0 AND MIT", Namespace: "alpine", Distro: "alpine-3.20.3"},
	}
	if !slices.Equal(info.Deps, want) {
		t.Errorf("Deps = %+v\nwant %+v", info.Deps, want)
	}
	if len(info.Image.Binaries) != 0 {
		t.Errorf("Binaries = %v, want none", info.Image.Binaries)
	}
}

func TestReadRemotePlatform(t *testing.T) {
	host := startRegistry(t)
	ref := host + "/multi:1"
	idx := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: fixtureImage(t, "linux/amd64", "image-alpine", nil), Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}},
		mutate.IndexAddendum{Add: fixtureImage(t, "linux/arm64", "image-debian", nil), Platform: &v1.Platform{OS: "linux", Architecture: "arm64"}},
	)
	r, _ := name.ParseReference(ref)
	if err := remote.WriteIndex(r, idx); err != nil {
		t.Fatal(err)
	}

	info, err := Read(context.Background(), ref, "", Options{Platform: "linux/arm64"})
	if err != nil {
		t.Fatal(err)
	}
	if info.Image.Platform != "linux/arm64" || info.Image.Distro != "debian-12" {
		t.Errorf("Platform = %q, Distro = %q; want the arm64 debian image", info.Image.Platform, info.Image.Distro)
	}

	_, err = Read(context.Background(), ref, "", Options{Platform: "linux/s390x"})
	if err == nil || !strings.Contains(err.Error(), "available platforms: linux/amd64, linux/arm64") {
		t.Errorf("err = %v, want the available platforms listed", err)
	}
}

func TestReadRemoteErrors(t *testing.T) {
	host := startRegistry(t)
	tests := map[string]Options{
		"Invalid::ref":        {},
		host + "/missing:1":   {Platform: "linux/amd64"},
		host + "/whatever:1x": {Platform: "not a platform/"},
	}
	for ref, opts := range tests {
		if _, err := Read(context.Background(), ref, "", opts); err == nil {
			t.Errorf("Read(%q, %+v): expected an error", ref, opts)
		}
	}
}

func TestReadWhiteout(t *testing.T) {
	files, err := testimage.DirFiles(fixtures + "image-alpine")
	if err != nil {
		t.Fatal(err)
	}
	base, err := testimage.Layer(files)
	if err != nil {
		t.Fatal(err)
	}
	upper, err := testimage.Layer(map[string][]byte{apkDB: nil})
	if err != nil {
		t.Fatal(err)
	}
	img, err := testimage.Image("linux/amd64", base, upper)
	if err != nil {
		t.Fatal(err)
	}
	info, err := Read(context.Background(), "", writeArchive(t, img, "test/whiteout:1"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Deps) != 0 {
		t.Errorf("deleted apk database still read: %+v", info.Deps)
	}
}

func TestScanInfoDeduplicates(t *testing.T) {
	bin := selfBinary(t)
	img := fixtureImage(t, "linux/amd64", "image-alpine", map[string][]byte{"/bin/a": bin, "/bin/b": bin})
	info, err := Read(context.Background(), "", writeArchive(t, img, "test/dedup:1"), Options{Verbose: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(info.Image.Binaries, []string{"/bin/a", "/bin/b"}) {
		t.Errorf("Binaries = %v", info.Image.Binaries)
	}
	seen := map[string]bool{}
	for _, d := range info.Deps {
		key := d.Type + " " + d.Ref()
		if seen[key] {
			t.Errorf("%s listed twice", key)
		}
		seen[key] = true
	}
}

func TestScanInfoMainLicense(t *testing.T) {
	s := &scan{files: map[string][]byte{}}
	exe, _ := os.Executable()
	bi, err := buildinfo.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	bi.Main.Version = "v1.2.3" // even a published version is never looked up
	s.binaries = []binary{{path: "/app", bi: bi}}
	info, err := s.info()
	if err != nil {
		t.Fatal(err)
	}
	m := find(info, "", bi.Main.Path)
	if m == nil || m.License != "Unknown" {
		t.Errorf("main module = %+v, want license Unknown", m)
	}
}

func TestReadRemoteUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("DOCKER_CONFIG", t.TempDir()) // no stored credentials

	ref := strings.TrimPrefix(srv.URL, "http://") + "/private:1"
	_, err := Read(context.Background(), ref, "", Options{Platform: "linux/amd64"})
	if err == nil || !strings.Contains(err.Error(), "docker login") {
		t.Errorf("err = %v, want a docker login hint", err)
	}
}

// linkedImage writes an image whose tar has links, which testimage.Layer cannot express.
func linkedImage(t *testing.T, entries []tar.Header, contents map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, hdr := range entries {
		data := contents[hdr.Name]
		hdr.Size = int64(len(data))
		hdr.Mode = 0o644
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil })
	if err != nil {
		t.Fatal(err)
	}
	img, err := testimage.Image("linux/amd64", layer)
	if err != nil {
		t.Fatal(err)
	}
	return writeArchive(t, img, "test/links:1")
}

func TestReadLinks(t *testing.T) {
	const dep5 = "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n\nFiles: *\nLicense: "
	status := "Package: gcc-12-base\nVersion: 12\nArchitecture: amd64\n\nPackage: libgcc-s1\nVersion: 12\nArchitecture: amd64\n\n" +
		"Package: hardlinked\nVersion: 1\nArchitecture: amd64\n\nPackage: libc6\nVersion: 2.36\nArchitecture: amd64\n\n" +
		"Package: libc6\nVersion: 2.36\nArchitecture: i386\n"
	archive := linkedImage(t, []tar.Header{
		{Name: "usr/lib/os-release", Typeflag: tar.TypeReg},
		{Name: "etc/os-release", Typeflag: tar.TypeSymlink, Linkname: "../usr/lib/os-release"},
		{Name: "var/lib/dpkg/status", Typeflag: tar.TypeReg},
		{Name: "usr/share/doc/gcc-12-base/copyright", Typeflag: tar.TypeReg},
		{Name: "usr/share/doc/libgcc-s1", Typeflag: tar.TypeSymlink, Linkname: "gcc-12-base"},
		{Name: "usr/share/doc/hardlinked/copyright", Typeflag: tar.TypeLink, Linkname: "usr/share/doc/gcc-12-base/copyright"},
		{Name: "usr/lib/apk/db/installed", Typeflag: tar.TypeReg},
	}, map[string]string{
		"usr/lib/os-release":                  "ID=debian\nVERSION_ID=12\n",
		"var/lib/dpkg/status":                 status,
		"usr/share/doc/gcc-12-base/copyright": dep5 + "GPL-3+\n",
		"usr/lib/apk/db/installed":            "P:musl\nV:1\nL:MIT\n",
	})
	info, err := Read(context.Background(), "", archive, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if info.Image.Distro != "debian-12" {
		t.Errorf("Distro = %q, want debian-12 through the os-release symlink", info.Image.Distro)
	}
	for _, pkg := range []string{"gcc-12-base", "libgcc-s1", "hardlinked"} {
		if p := find(info, packages.TypeDeb, pkg); p == nil || p.License != "GPL-3.0-or-later" {
			t.Errorf("%s = %+v, want GPL-3.0-or-later", pkg, p)
		}
	}
	if p := find(info, packages.TypeAPK, "musl"); p == nil {
		t.Error("usr-merged apk database not read")
	}
	var archs []string
	for _, d := range info.Deps {
		if d.Path == "libc6" {
			archs = append(archs, d.Arch)
		}
	}
	if !slices.Equal(archs, []string{"amd64", "i386"}) {
		t.Errorf("libc6 archs = %v, want both multiarch packages", archs)
	}
}

func TestScanReadLinkLoop(t *testing.T) {
	s := &scan{files: map[string][]byte{}, links: map[string]string{"/a": "/b", "/b": "/a"}}
	if data := s.read("/a"); data != nil {
		t.Errorf("read through a link loop = %q, want nil", data)
	}
}

func TestReadPlatformMismatch(t *testing.T) {
	archive := writeArchive(t, fixtureImage(t, "linux/amd64", "image-alpine", nil), "test/amd64:1")
	if _, err := Read(context.Background(), "", archive, Options{Platform: "linux/arm64"}); err == nil || !strings.Contains(err.Error(), "linux/amd64") {
		t.Errorf("err = %v, want a platform mismatch", err)
	}
	if _, err := Read(context.Background(), "", archive, Options{Platform: "linux/amd64"}); err != nil {
		t.Errorf("matching platform: %v", err)
	}

	host := startRegistry(t)
	ref := host + "/single:1"
	r, _ := name.ParseReference(ref)
	if err := remote.Write(r, fixtureImage(t, "linux/amd64", "image-alpine", nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(context.Background(), ref, "", Options{Platform: "linux/arm64"}); err == nil {
		t.Error("single-platform image read for another platform")
	}
}

// testimageLayer builds a single-layer linux/amd64 image from files.
func testimageLayer(files map[string][]byte) (v1.Image, error) {
	layer, err := testimage.Layer(files)
	if err != nil {
		return nil, err
	}
	return testimage.Image("linux/amd64", layer)
}
