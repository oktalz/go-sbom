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
	fmt.Fprintf(tw, "Go version:\t%s\n", info.GoVersion)
	fmt.Fprintf(tw, "Module:\t%s\n", info.Path)
	mainLine := info.Main.Ref()
	if info.Main.License != "" {
		mainLine += " (" + info.Main.License + ")"
	}
	fmt.Fprintf(tw, "Main:\t%s\n", mainLine)
	fmt.Fprintln(tw)
	if links {
		fmt.Fprint(tw, "PACKAGE\tVERSION\tLICENSE\tLINK\n")
	} else {
		fmt.Fprint(tw, "PACKAGE\tVERSION\tLICENSE\n")
	}
	for i := range info.Deps {
		dep := &info.Deps[i]
		pkg := dep.Effective()
		replaces := ""
		if dep.Replace != nil {
			replaces = "\t(replaces " + dep.Ref() + ")"
		}
		if links {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s%s\n", pkg.Path, pkg.Version, pkg.License, pkg.LicenseLink, replaces)
		} else {
			fmt.Fprintf(tw, "%s\t%s\t%s%s\n", pkg.Path, pkg.Version, pkg.License, replaces)
		}
	}
	return tw.Flush()
}

func writeCSV(info *packages.Info, w io.Writer, links bool) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	header := []string{"package", "version", "license"}
	if links {
		header = append(header, "link")
	}
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
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	return cw.Error()
}

type jsonOutput struct {
	GoVersion    string           `json:"go_version"`
	Module       string           `json:"module"`
	Main         jsonPackage      `json:"main"`
	Dependencies []jsonDependency `json:"dependencies"`
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
		}
		if links {
			d.Link = pkg.LicenseLink
		}
		out.Dependencies = append(out.Dependencies, d)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func writeYAML(info *packages.Info, out io.Writer, links bool) error {
	// bufio.Writer keeps the first write error and reports it from Flush.
	w := bufio.NewWriter(out)
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
		purl := goPurl(info.Main.Path, info.Main.Version)
		main := cdxComponent{
			Type:     "application",
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
		purl := goPurl(pkg.Path, pkg.Version)
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

	if info.Main.Path != "" {
		mainPkg := spdxPackage{
			SPDXID:                spdxID(info.Main.Path, info.Main.Version),
			Name:                  info.Main.Path,
			VersionInfo:           info.Main.Version,
			DownloadLocation:      "NOASSERTION",
			CopyrightText:         "NOASSERTION",
			PrimaryPackagePurpose: "APPLICATION",
			LicenseConcluded:      license(info.Main.License),
			LicenseDeclared:       license(info.Main.License),
			ExternalRefs:          spdxPurlRef(info.Main.Path, info.Main.Version),
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
		sp := spdxPackage{
			SPDXID:                spdxID(pkg.Path, pkg.Version),
			Name:                  pkg.Path,
			VersionInfo:           pkg.Version,
			DownloadLocation:      "NOASSERTION",
			CopyrightText:         "NOASSERTION",
			PrimaryPackagePurpose: "LIBRARY",
			LicenseConcluded:      license(pkg.License),
			LicenseDeclared:       license(pkg.License),
			ExternalRefs:          spdxPurlRef(pkg.Path, pkg.Version),
		}
		doc.Packages = append(doc.Packages, sp)

		if info.Main.Path != "" {
			doc.Relationships = append(doc.Relationships, spdxRelationship{
				SPDXElementID:      spdxID(info.Main.Path, info.Main.Version),
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

func spdxPurlRef(modulePath, version string) []spdxExternalRef {
	purl := goPurl(modulePath, version)
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
