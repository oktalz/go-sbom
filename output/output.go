package output

import (
	"bufio"
	"cmp"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/oktalz/go-sbom/packages"
	toolversion "github.com/oktalz/go-sbom/version"
	"golang.org/x/mod/modfile"
)

// Formats lists the values accepted as an explicit output format.
// "spdx" picks the SPDX version from the spdx-version setting (see [SPDXFormat]);
// "spdx2" and "spdx3" pick it explicitly.
var Formats = []string{"text", "csv", "yaml", "json", "cyclonedx", "spdx", "spdx2", "spdx3"}

// DefaultSPDXVersion is used for "spdx" / .spdx.json when no version is set.
const DefaultSPDXVersion = "2"

// SPDXFormat maps an spdx-version setting to the versioned format name.
// It accepts "2"/"2.3" (SPDX 2.3) and "3"/"3.0"/"3.0.1" (SPDX 3.0.1);
// an empty value means [DefaultSPDXVersion].
func SPDXFormat(version string) (string, error) {
	switch strings.TrimSpace(version) {
	case "", "2", "2.3":
		return "spdx2", nil
	case "3", "3.0", "3.0.1":
		return "spdx3", nil
	default:
		return "", fmt.Errorf("unsupported SPDX version %q (use 2 for SPDX 2.3 or 3 for SPDX 3.0.1)", version)
	}
}

// ResolveFormat returns the output format for path and an optional explicit
// format, resolving "spdx" (from --format spdx or .spdx.json) with spdxVersion.
// An empty result means the default text output to stdout.
func ResolveFormat(path, format, spdxVersion string) (string, error) {
	if format == "" && path != "" {
		var err error
		if format, err = FormatFromPath(path); err != nil {
			return "", err
		}
	}
	if format == "spdx" {
		return SPDXFormat(spdxVersion)
	}
	return format, nil
}

// IsFormat reports whether f is one of [Formats].
func IsFormat(f string) bool {
	return slices.Contains(Formats, f)
}

// FormatFromPath returns the output format implied by a file name's extension.
func FormatFromPath(path string) (string, error) {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".cyclonedx.json"), strings.HasSuffix(lower, ".cdx.json"):
		return "cyclonedx", nil
	case strings.HasSuffix(lower, ".spdx2.json"):
		return "spdx2", nil
	case strings.HasSuffix(lower, ".spdx3.json"):
		return "spdx3", nil
	case strings.HasSuffix(lower, ".spdx.json"):
		return "spdx", nil
	}
	switch ext := filepath.Ext(lower); ext {
	case ".csv":
		return "csv", nil
	case ".yml", ".yaml":
		return "yaml", nil
	case ".json":
		return "json", nil
	case ".txt":
		return "text", nil
	default:
		return "", fmt.Errorf("unsupported output format %q (use .txt, .yml, .csv, .json, .cyclonedx.json, .cdx.json, .spdx.json, .spdx2.json, or .spdx3.json)", ext)
	}
}

// Write outputs info to the given file path. The format is determined by the
// file extension (.txt, .yml, .csv, .json, .cyclonedx.json, .cdx.json, .spdx.json, .spdx2.json, .spdx3.json).
// Format "spdx" (and .spdx.json) means SPDX 2.3 here; use [ResolveFormat] to
// honour a configured SPDX version.
// If format is non-empty, it overrides the extension-based detection.
// If path is empty, output goes to stdout (as a text table unless format is set).
// The format is resolved before the file is created, so an unsupported
// format never leaves an empty file behind.
func Write(info *packages.Info, path, format string, links bool) error {
	if format == "" && path != "" {
		var err error
		if format, err = FormatFromPath(path); err != nil {
			return err
		}
	}
	if format == "" {
		format = "text"
	}
	if !IsFormat(format) {
		return fmt.Errorf("unsupported format %q", format)
	}

	sortDeps(info)

	if path == "" {
		return writeFormat(info, os.Stdout, format, links)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	if err := writeFormat(info, f, format, links); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing output file: %w", err)
	}
	return nil
}

func writeFormat(info *packages.Info, w io.Writer, format string, links bool) error {
	switch format {
	case "text":
		return writeText(info, w, links)
	case "csv":
		return writeCSV(info, w, links)
	case "yaml":
		return writeYAML(info, w, links)
	case "json":
		return writeJSON(info, w, links)
	case "cyclonedx":
		return writeCycloneDX(info, w)
	case "spdx", "spdx2":
		return writeSPDX(info, w)
	case "spdx3":
		return writeSPDX3(info, w)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

// sbomTime returns the SBOM creation time: SOURCE_DATE_EPOCH when set (for
// reproducible builds), otherwise the current time.
func sbomTime() string {
	t := time.Now()
	if s := os.Getenv("SOURCE_DATE_EPOCH"); s != "" {
		if sec, err := strconv.ParseInt(s, 10, 64); err == nil {
			t = time.Unix(sec, 0)
		} else {
			fmt.Fprintf(os.Stderr, "warning: ignoring invalid SOURCE_DATE_EPOCH %q\n", s)
		}
	}
	return t.UTC().Format(time.RFC3339)
}

func sortDeps(info *packages.Info) {
	slices.SortFunc(info.Deps, func(a, b packages.Package) int {
		if c := cmp.Compare(a.License, b.License); c != 0 {
			return c
		}
		return cmp.Compare(a.Path, b.Path)
	})
}

func writeText(info *packages.Info, w io.Writer, links bool) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	writeTextHeader(info, tw)
	fmt.Fprintln(tw)
	header := "PACKAGE\tVERSION\tLICENSE"
	if links {
		header += "\tLINK"
	}
	if info.Image != nil {
		header += "\tTYPE"
	}
	fmt.Fprintln(tw, header)
	for i := range info.Deps {
		dep := &info.Deps[i]
		pkg := dep.Effective()
		line := pkg.Path + "\t" + pkg.Version + "\t" + pkg.License
		if links {
			line += "\t" + pkg.LicenseLink
		}
		if info.Image != nil {
			line += "\t" + typeName(pkg)
		}
		if dep.Replace != nil {
			line += "\t(replaces " + dep.Ref() + ")"
		}
		fmt.Fprintln(tw, line)
	}
	return tw.Flush()
}

func writeTextHeader(info *packages.Info, tw io.Writer) {
	if img := info.Image; img != nil {
		fmt.Fprintf(tw, "Image:\t%s\n", img.Ref)
		fmt.Fprintf(tw, "Digest:\t%s\n", img.Digest)
		fmt.Fprintf(tw, "Platform:\t%s\n", img.Platform)
		if img.Distro != "" {
			fmt.Fprintf(tw, "Distro:\t%s\n", img.Distro)
		}
		for _, b := range img.Binaries {
			fmt.Fprintf(tw, "Go binary:\t%s\n", b)
		}
		return
	}
	fmt.Fprintf(tw, "Go version:\t%s\n", info.GoVersion)
	fmt.Fprintf(tw, "Module:\t%s\n", info.Path)
	mainLine := info.Main.Ref()
	if info.Main.License != "" {
		mainLine += " (" + info.Main.License + ")"
	}
	fmt.Fprintf(tw, "Main:\t%s\n", mainLine)
}

// typeName names a package type in text, CSV, YAML and JSON output.
func typeName(p *packages.Package) string {
	if p.Type == "" {
		return "go"
	}
	return p.Type
}

// outputType is the type field of YAML and JSON, only set for images.
func outputType(info *packages.Info, p *packages.Package) string {
	if info.Image == nil {
		return ""
	}
	return typeName(p)
}

func writeCSV(info *packages.Info, w io.Writer, links bool) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	header := []string{"package", "version", "license"}
	if links {
		header = append(header, "link")
	}
	header = append(header, "type")
	if err := cw.Write(header); err != nil {
		return err
	}
	for i := range info.Deps {
		dep := &info.Deps[i]
		pkg := dep.Effective()
		row := []string{pkg.Path, pkg.Version, pkg.License}
		if links {
			row = append(row, pkg.LicenseLink)
		}
		row = append(row, typeName(pkg))
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	return cw.Error()
}

type jsonOutput struct {
	Image        *jsonImage       `json:"image,omitempty"`
	GoVersion    string           `json:"go_version"`
	Module       string           `json:"module"`
	Main         jsonPackage      `json:"main"`
	Dependencies []jsonDependency `json:"dependencies"`
}

type jsonImage struct {
	Ref      string   `json:"ref"`
	Digest   string   `json:"digest"`
	Platform string   `json:"platform"`
	Distro   string   `json:"distro,omitempty"`
	Binaries []string `json:"go_binaries,omitempty"`
}

type jsonPackage struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	License string `json:"license,omitempty"`
}

type jsonDependency struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	License string `json:"license"`
	Link    string `json:"link,omitempty"`
	Replace string `json:"replaces,omitempty"`
	Type    string `json:"type,omitempty"`
}

func writeJSON(info *packages.Info, w io.Writer, links bool) error {
	out := jsonOutput{
		GoVersion: info.GoVersion,
		Module:    info.Path,
		Main: jsonPackage{
			Path:    info.Main.Path,
			Version: info.Main.Version,
			License: info.Main.License,
		},
	}
	if img := info.Image; img != nil {
		out.Image = &jsonImage{Ref: img.Ref, Digest: img.Digest, Platform: img.Platform, Distro: img.Distro, Binaries: img.Binaries}
	}

	for i := range info.Deps {
		dep := &info.Deps[i]
		pkg := dep.Effective()
		replaces := ""
		if dep.Replace != nil {
			replaces = dep.Path + "@" + dep.Version
		}
		d := jsonDependency{
			Path:    pkg.Path,
			Version: pkg.Version,
			License: pkg.License,
			Replace: replaces,
			Type:    outputType(info, pkg),
		}
		if links {
			d.Link = pkg.LicenseLink
		}
		out.Dependencies = append(out.Dependencies, d)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // purl qualifiers use &
	return enc.Encode(out)
}

func writeYAML(info *packages.Info, out io.Writer, links bool) error {
	// bufio.Writer keeps the first write error and reports it from Flush.
	w := bufio.NewWriter(out)
	if img := info.Image; img != nil {
		fmt.Fprint(w, "image:\n")
		fmt.Fprintf(w, "  ref: %s\n", img.Ref)
		fmt.Fprintf(w, "  digest: %s\n", img.Digest)
		fmt.Fprintf(w, "  platform: %s\n", img.Platform)
		if img.Distro != "" {
			fmt.Fprintf(w, "  distro: %s\n", img.Distro)
		}
		if len(img.Binaries) > 0 {
			fmt.Fprint(w, "  go_binaries:\n")
			for _, b := range img.Binaries {
				fmt.Fprintf(w, "    - %s\n", b)
			}
		}
	}
	fmt.Fprintf(w, "go_version: %s\n", info.GoVersion)
	fmt.Fprintf(w, "module: %s\n", info.Path)
	fmt.Fprint(w, "main:\n")
	fmt.Fprintf(w, "  path: %s\n", info.Main.Path)
	fmt.Fprintf(w, "  version: %s\n", info.Main.Version)
	if info.Main.License != "" {
		fmt.Fprintf(w, "  license: %s\n", info.Main.License)
	}
	fmt.Fprint(w, "dependencies:\n")
	for i := range info.Deps {
		dep := &info.Deps[i]
		pkg := dep.Effective()
		replaces := ""
		if dep.Replace != nil {
			replaces = dep.Path + "@" + dep.Version
		}
		fmt.Fprintf(w, "  - package: %s\n", pkg.Path)
		fmt.Fprintf(w, "    version: %s\n", pkg.Version)
		fmt.Fprintf(w, "    license: %s\n", pkg.License)
		if links && pkg.LicenseLink != "" {
			fmt.Fprintf(w, "    link: %s\n", pkg.LicenseLink)
		}
		if replaces != "" {
			fmt.Fprintf(w, "    replaces: %s\n", replaces)
		}
		if t := outputType(info, pkg); t != "" {
			fmt.Fprintf(w, "    type: %s\n", t)
		}
	}
	return w.Flush()
}

// CycloneDX spec version written by writeCycloneDX.
const (
	cdxSpecVersion = "1.7"
	cdxSchemaURL   = "https://cyclonedx.org/schema/bom-1.7.schema.json"
)

type cdxBOM struct {
	Schema       string         `json:"$schema"`
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber"`
	Metadata     cdxMetadata    `json:"metadata"`
	Components   []cdxComponent `json:"components,omitempty"`
	Version      int            `json:"version"`
}

type cdxMetadata struct {
	Component *cdxComponent `json:"component,omitempty"`
	Timestamp string        `json:"timestamp"`
	Tools     cdxTools      `json:"tools"`
}

// cdxTools is the object form of metadata.tools; the legacy array form is
// deprecated since CycloneDX 1.5.
type cdxTools struct {
	Components []cdxComponent `json:"components"`
}

type cdxComponent struct {
	Type     string       `json:"type"`
	BOMRef   string       `json:"bom-ref,omitempty"`
	Name     string       `json:"name"`
	Version  string       `json:"version,omitempty"`
	Purl     string       `json:"purl,omitempty"`
	Licenses []cdxLicense `json:"licenses,omitempty"`
}

// cdxLicense is a CycloneDX license choice: either a single license (by SPDX
// id, or by name when it is not an SPDX id) or an SPDX expression.
type cdxLicense struct {
	License    *cdxLicenseEntry `json:"license,omitempty"`
	Expression string           `json:"expression,omitempty"`
}

type cdxLicenseEntry struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

func writeCycloneDX(info *packages.Info, w io.Writer) error {
	bom := cdxBOM{
		BOMFormat:    "CycloneDX",
		Schema:       cdxSchemaURL,
		SpecVersion:  cdxSpecVersion,
		SerialNumber: "urn:uuid:" + deterministicUUID(info),
		Version:      1,
		Metadata: cdxMetadata{
			Timestamp: sbomTime(),
			Tools: cdxTools{Components: []cdxComponent{{
				Type:    "application",
				Name:    toolName,
				Version: toolversion.Version,
			}}},
		},
	}

	if info.Main.Path != "" {
		purl := purl(&info.Main)
		main := cdxComponent{
			Type:     mainPurpose(info, "application", "container"),
			BOMRef:   purl,
			Name:     info.Main.Path,
			Version:  info.Main.Version,
			Purl:     purl,
			Licenses: cdxLicenses(info.Main.License),
		}
		bom.Metadata.Component = &main
	}

	seenRefs := map[string]bool{}
	if bom.Metadata.Component != nil {
		seenRefs[bom.Metadata.Component.BOMRef] = true
	}
	for i := range info.Deps {
		dep := &info.Deps[i]
		pkg := dep.Effective()
		purl := purl(pkg)
		bomRef := purl
		if seenRefs[bomRef] {
			bomRef = "" // bom-ref must be unique within the BOM
		}
		seenRefs[bomRef] = true
		comp := cdxComponent{
			Type:     "library",
			BOMRef:   bomRef,
			Name:     pkg.Path,
			Version:  pkg.Version,
			Purl:     purl,
			Licenses: cdxLicenses(pkg.License),
		}
		bom.Components = append(bom.Components, comp)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // purl qualifiers use &
	return enc.Encode(bom)
}

// cdxLicenses converts a detected or user-set license into CycloneDX form.
// CycloneDX only allows SPDX ids in license.id, so anything else goes in
// license.name; compound SPDX expressions go in expression.
func cdxLicenses(license string) []cdxLicense {
	if license == "" || license == "Unknown" {
		return nil
	}
	expr, single, ok := canonicalSPDX(license)
	switch {
	case ok && single && !strings.Contains(expr, "LicenseRef-") && !strings.HasSuffix(expr, "+"):
		return []cdxLicense{{License: &cdxLicenseEntry{ID: expr}}}
	case ok:
		return []cdxLicense{{Expression: expr}}
	default:
		return []cdxLicense{{License: &cdxLicenseEntry{Name: license}}}
	}
}

// mainPurpose picks the purpose of the main package: app for Go input, image for images.
func mainPurpose(info *packages.Info, app, image string) string {
	if info.Main.Type == packages.TypeOCI {
		return image
	}
	return app
}

// purl returns the Package URL of p, or "" when it has none.
func purl(p *packages.Package) string {
	q := url.Values{}
	if p.Arch != "" {
		q.Set("arch", p.Arch)
	}
	var s string
	switch p.Type {
	case "":
		return goPurl(p.Path, p.Version)
	case packages.TypeOCI:
		// The digest's ':' is encoded, as in the purl spec's oci examples.
		name := p.Path[strings.LastIndex(p.Path, "/")+1:]
		s = "pkg:oci/" + purlEscape(strings.ToLower(name)) + "@" + url.QueryEscape(p.Version)
		if strings.Contains(p.Path, "/") { // an archive without a tag has no repository
			q.Set("repository_url", p.Path)
		}
	default:
		s = "pkg:" + p.Type + "/"
		if p.Namespace != "" {
			s += purlEscape(p.Namespace) + "/"
		}
		s += purlEscape(p.Path)
		version := p.Version
		if epoch, rest, ok := strings.Cut(version, ":"); ok && p.Type == packages.TypeRPM {
			q.Set("epoch", epoch) // the rpm purl carries the epoch as a qualifier
			version = rest
		}
		if version != "" {
			s += "@" + purlEscape(version)
		}
		if p.Distro != "" {
			q.Set("distro", p.Distro)
		}
	}
	if len(q) > 0 {
		s += "?" + strings.ReplaceAll(q.Encode(), "%2F", "/") // the spec examples keep '/' in repository_url
	}
	return s
}

// purlEscape percent-encodes a purl name or version, '+' included as other tools do.
func purlEscape(s string) string {
	return strings.ReplaceAll(url.PathEscape(s), "+", "%2B")
}

func goPurl(modulePath, version string) string {
	if modulePath == "" || modfile.IsDirectoryPath(modulePath) {
		return ""
	}
	// Package URL spec: pkg:golang/<namespace>/<name>@<version>.
	// The version is optional (a go.mod main module has none) and must be
	// percent-encoded ("+incompatible" -> "%2Bincompatible").
	if version == "" {
		return "pkg:golang/" + modulePath
	}
	return fmt.Sprintf("pkg:golang/%s@%s", modulePath, strings.ReplaceAll(version, "+", "%2B"))
}

type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
	ExtractedLicenses []spdxExtracted    `json:"hasExtractedLicensingInfos,omitempty"`
}

// spdxExtracted declares a LicenseRef- used for a license that has no SPDX id.
type spdxExtracted struct {
	LicenseID     string `json:"licenseId"`
	ExtractedText string `json:"extractedText"`
	Name          string `json:"name"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID                string            `json:"SPDXID"`
	Name                  string            `json:"name"`
	VersionInfo           string            `json:"versionInfo,omitempty"`
	DownloadLocation      string            `json:"downloadLocation"`
	LicenseConcluded      string            `json:"licenseConcluded"`
	LicenseDeclared       string            `json:"licenseDeclared"`
	CopyrightText         string            `json:"copyrightText"`
	PrimaryPackagePurpose string            `json:"primaryPackagePurpose,omitempty"`
	ExternalRefs          []spdxExternalRef `json:"externalRefs,omitempty"`
	FilesAnalyzed         bool              `json:"filesAnalyzed"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
	RelationshipType   string `json:"relationshipType"`
}

func writeSPDX(info *packages.Info, w io.Writer) error {
	doc := spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              info.Main.Path,
		DocumentNamespace: fmt.Sprintf("https://spdx.org/spdxdocs/%s-%s", info.Main.Path, deterministicUUID(info)),
		CreationInfo: spdxCreationInfo{
			Created:  sbomTime(),
			Creators: []string{"Tool: github.com/oktalz/go-sbom"},
		},
	}

	refs := map[string]string{} // LicenseRef- id -> original name
	license := func(l string) string { return spdxLicense(l, refs) }
	ids := newSPDXIDSet()
	mainID, _ := ids.id(&info.Main)

	if info.Main.Path != "" {
		mainPkg := spdxPackage{
			SPDXID:                mainID,
			Name:                  info.Main.Path,
			VersionInfo:           info.Main.Version,
			DownloadLocation:      "NOASSERTION",
			CopyrightText:         "NOASSERTION",
			PrimaryPackagePurpose: mainPurpose(info, "APPLICATION", "CONTAINER"),
			LicenseConcluded:      license(info.Main.License),
			LicenseDeclared:       license(info.Main.License),
			ExternalRefs:          spdxPurlRef(&info.Main),
		}
		doc.Packages = append(doc.Packages, mainPkg)
		doc.Relationships = append(doc.Relationships, spdxRelationship{
			SPDXElementID:      "SPDXRef-DOCUMENT",
			RelatedSPDXElement: mainPkg.SPDXID,
			RelationshipType:   "DESCRIBES",
		})
	}

	for i := range info.Deps {
		dep := &info.Deps[i]
		pkg := dep.Effective()
		id, isNew := ids.id(pkg)
		if !isNew {
			continue // several modules replaced by the same one
		}
		sp := spdxPackage{
			SPDXID:                id,
			Name:                  pkg.Path,
			VersionInfo:           pkg.Version,
			DownloadLocation:      "NOASSERTION",
			CopyrightText:         "NOASSERTION",
			PrimaryPackagePurpose: "LIBRARY",
			LicenseConcluded:      license(pkg.License),
			LicenseDeclared:       license(pkg.License),
			ExternalRefs:          spdxPurlRef(pkg),
		}
		doc.Packages = append(doc.Packages, sp)

		if info.Main.Path != "" {
			doc.Relationships = append(doc.Relationships, spdxRelationship{
				SPDXElementID:      mainID,
				RelatedSPDXElement: sp.SPDXID,
				RelationshipType:   "DEPENDS_ON",
			})
		}
	}

	for _, id := range slices.Sorted(maps.Keys(refs)) {
		doc.ExtractedLicenses = append(doc.ExtractedLicenses, spdxExtracted{
			LicenseID:     id,
			Name:          refs[id],
			ExtractedText: "License text not included; license identified as \"" + refs[id] + "\" by go-sbom.",
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // purl qualifiers use &
	return enc.Encode(doc)
}

// spdxID builds an SPDX element id; only letters, digits, '.' and '-' are allowed.
func spdxID(modulePath, version string) string {
	s := modulePath
	if version != "" {
		s += "@" + version
	}
	return "SPDXRef-" + invalidRefRe.ReplaceAllString(s, "-")
}

// pkgSPDXID is the element id of p; OS packages are prefixed with their type.
func pkgSPDXID(p *packages.Package) string {
	if p.Type == "" || p.Type == packages.TypeOCI {
		return spdxID(p.Path, p.Version)
	}
	return spdxID(p.Type+"-"+p.Path, p.Version)
}

// spdxIDSet gives each distinct package one element id, suffixed when ids clash.
type spdxIDSet struct {
	byKey map[string]string
	used  map[string]bool
}

func newSPDXIDSet() *spdxIDSet {
	return &spdxIDSet{byKey: map[string]string{}, used: map[string]bool{}}
}

// id returns the element id of p and whether p was not seen before.
func (s *spdxIDSet) id(p *packages.Package) (string, bool) {
	key := p.Type + " " + p.Ref() + " " + p.Arch
	if id, ok := s.byKey[key]; ok {
		return id, false
	}
	base := pkgSPDXID(p)
	id := base
	for n := 2; s.used[id]; n++ {
		id = fmt.Sprintf("%s-%d", base, n)
	}
	s.byKey[key], s.used[id] = id, true
	return id, true
}

// spdxLicense converts a license into a valid SPDX license expression.
// Names that are not SPDX ids become LicenseRef- ids, recorded in refs so they
// can be declared in hasExtractedLicensingInfos.
func spdxLicense(license string, refs map[string]string) string {
	if license == "" || license == "Unknown" {
		return "NOASSERTION"
	}
	if expr, _, ok := canonicalSPDX(license); ok {
		return expr
	}
	ref := licenseRef(license)
	refs[ref] = license
	return ref
}

func spdxPurlRef(p *packages.Package) []spdxExternalRef {
	purl := purl(p)
	if purl == "" {
		return nil
	}
	return []spdxExternalRef{{
		ReferenceCategory: "PACKAGE-MANAGER",
		ReferenceType:     "purl",
		ReferenceLocator:  purl,
	}}
}

// deterministicUUID generates a UUID v5-style identifier from the SBOM content.
// This makes SPDX output reproducible for the same set of dependencies.
func deterministicUUID(info *packages.Info) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s@%s", info.Main.Path, info.Main.Version)
	for i := range info.Deps {
		dep := &info.Deps[i]
		pkg := dep.Effective()
		fmt.Fprintf(h, "\n%s@%s:%s", pkg.Path, pkg.Version, pkg.License)
	}
	sum := h.Sum(nil)
	// Format as UUID v5 (SHA-based)
	sum[6] = (sum[6] & 0x0f) | 0x50 // version 5
	sum[8] = (sum[8] & 0x3f) | 0x80 // variant 1
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}
