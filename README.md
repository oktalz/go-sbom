<p align="center">
  <img src="logo/gopher.svg" alt="go-sbom gopher holding a security shield" width="180">
</p>

## go-sbom

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

### Description

A tool for extracting Software Bill of Materials (SBOM) from Go binaries and `go.mod` files. It detects all dependency packages, classifies their licenses, and can enforce license policies in CI/CD pipelines.

### Features

- Extract dependencies from compiled Go binaries or `go.mod` files
- Analyze container images from a registry or a `docker save` tarball: the Go modules of every Go binary, plus Alpine (apk), Debian/Ubuntu (dpkg) and RPM (RHEL, Fedora, SUSE, Amazon Linux) packages with their licenses
- Automatic license detection using [Google's License Classifier](https://github.com/google/licenseclassifier)
- Manual license assignment with `--licence` flag (repeatable)
- License policy enforcement with `--check` against an `--allowed` list, with `--exclude` for internal modules
- Config file (`.go-sbom.yml`) for any flag, plus `GO_SBOM_*` environment variables
- JUnit XML report generation for CI/CD integration
- Multiple output formats: text, CSV, YAML, JSON, CycloneDX 1.7 JSON, SPDX 2.3 JSON, SPDX 3.0.1 JSON-LD, all checked in CI against the official schemas
- Reproducible SBOMs with `SOURCE_DATE_EPOCH`
- Format override with `--format` (independent of output file extension)
- Configurable minimum confidence threshold for license classification (`--min-confidence`)
- Optional links to license files
- CGO detection: warns when a binary was built with CGO, as C dependencies are not tracked
- Finds licenses in local replace directories, the module cache and the module proxy, respecting `GOPROXY`, `GOPRIVATE`/`GONOPROXY` and `go env`

### Installation

The recommended way is `go install` (needs Go 1.27 or newer):

```bash
go install github.com/oktalz/go-sbom@latest
```

This puts `go-sbom` in `$(go env GOPATH)/bin` (or `GOBIN`); make sure that directory is on your `PATH`. Use a version instead of `latest` (e.g. `@v0.1.0`) to pin it, for example in CI.

Prebuilt binaries for Linux, macOS and Windows (amd64 and arm64) are attached to each [GitHub release](https://github.com/oktalz/go-sbom/releases), together with `checksums.txt` and an SBOM of every binary in CycloneDX (`.cyclonedx.json`), SPDX 2.3 (`.spdx2.json`) and SPDX 3.0.1 (`.spdx3.json`). Each binary has signed build provenance and SBOM attestations, which the [GitHub CLI](https://cli.github.com/) can check:

```bash
gh attestation verify go-sbom_v0.1.0_linux_amd64 --repo oktalz/go-sbom
gh attestation verify go-sbom_v0.1.0_linux_amd64 --repo oktalz/go-sbom --predicate-type https://cyclonedx.org/bom
```

### Usage

```
                 ____  ____   ___  __  __
   __ _  ___    / ___|| __ ) / _ \|  \/  |
  / _` |/ _ \   \___ \|  _ \| | | | |\/| |
 | (_| | (_) |   ___) | |_) | |_| | |  | |
  \__, |\___/   |____/|____/ \___/|_|  |_|
  |___/

NAME
  go-sbom

FLAGS
      --spdx-version STRING      SPDX version used by --format spdx and .spdx.json: 2 (SPDX 2.3) or 3 (SPDX 3.0.1) (default: 2)
  -a, --allowed STRING           allowed licenses for --check, comma-separated or repeatable (e.g. MIT,Apache-2.0)
  -e, --exclude STRING           module path prefixes or globs to skip in --check, comma-separated or repeatable (e.g. company.com/internal)
      --licence STRING           set license for a package (e.g. company.com/pkg:MIT, repeatable)
  -f, --file STRING              file to analyze (binary or go.mod); can also be given as the first argument
      --image STRING             container image to analyze, pulled from its registry (e.g. alpine:3.20)
      --image-archive STRING     container image to analyze, from a docker save tarball
      --platform STRING          platform of a multi-platform --image, as os/arch[/variant] (default: linux/<arch of go-sbom>)
  -o, --output STRING            output file (.txt, .yml, .csv, .json, .cyclonedx.json or .cdx.json, .spdx.json, .spdx2.json, .spdx3.json)
      --format STRING            output format override (text, csv, yaml, json, cyclonedx, spdx, spdx2, spdx3)
  -c, --config STRING            YAML config file with flag values (default: .go-sbom.yml or .go-sbom.yaml)
      --junit-file STRING        write a JUnit XML report of the license check (used with --check)
      --min-confidence FLOAT64   minimum confidence threshold for license classification (0.0-1.0) (default: 0)
      --image-timeout DURATION   time limit for pulling and reading the image (0 for none) (default: 10m0s)
      --check                    check licenses against --allowed and exit 2 on violations (no SBOM is written)
  -v, --version                  show version
  -h, --help                     show this help message
  -l, --links                    include links to license files in output
      --verbose                  enable verbose/debug logging
```

#### Analyze a Go binary

```bash
go-sbom /path/to/binary      # same as: go-sbom -f /path/to/binary
```

A binary records its modules and versions but no license texts. Dependency licenses are looked up in the module cache or the proxy; the main module's own license is not, so set it with `--licence` if you need it (e.g. `--licence github.com/example/myapp:MIT`).

#### Analyze a container image

```bash
go-sbom --image alpine:3.20                          # pulled from its registry
go-sbom --image ghcr.io/org/app:1.0 --platform linux/arm64
docker save app:1.0 -o app.tar && go-sbom --image-archive app.tar
```

The SBOM lists:

- the Go modules of every Go binary in the image, with licenses found as for a binary,
- the main module of each Go binary, with license `Unknown`, as for a binary (set it with `--licence`),
- the apk, dpkg and rpm packages, including distroless `status.d` entries.

The image is named by its manifest digest. A `docker save` tarball is named by its image ID (the config digest, as `docker images --no-trunc` shows), because the tarball has no registry manifest. The Go version of each binary is not recorded.

Notes:

- Registry credentials come from the Docker config (`docker login`) and its credential helpers.
- `--platform` picks the image of a multi-platform index. The default is `linux/` plus the architecture of go-sbom. For a single-platform image or a tarball, a given `--platform` must match the image.
- `--image-timeout` limits pulling and reading the image (default `10m`, `0` for no limit).
- Alpine packages carry their license in the package database.
- Debian package licenses come from `/usr/share/doc/<package>/copyright`. Only machine-readable (DEP-5) files are read; others give `Unknown`. Licenses of `Files: debian/*` stanzas are left out: they cover the packaging, not the package.
- RPM databases in all three formats are read: SQLite, NDB and BerkeleyDB. Only the first one found counts, so a database left over from a migration is ignored. Versions carry the epoch as `epoch:version-release`. Old Fedora license names with one clear SPDX id are converted (`GPLv2+` becomes `GPL-2.0-or-later`); others, such as `BSD`, stay as they are.
- The purl namespace is the `ID` of `/etc/os-release`, e.g. `rhel` or `amzn`. Some tools use `redhat` for RHEL, so purls may not match theirs.
- A warning is printed when the image has an `/etc/os-release` but no package database.
- `--check`, `--exclude` and `--licence` match OS packages by name, e.g. `--licence busybox:GPL-2.0-only`.
- Other ecosystems (npm, pip, jars) are not listed.
- `--file`, `--image` and `--image-archive` are mutually exclusive. The command line beats the environment, which beats the config file. So `--image` works in a directory whose `.go-sbom.yml` sets `file:`.

#### Analyze a go.mod file

```bash
go-sbom -f go.mod
```

#### Export to CSV

```bash
go-sbom -f go.mod -o sbom.csv
```

The last column, `type`, is `go` for Go modules and `apk`, `deb` or `rpm` for OS packages of a container image.

#### Export to YAML with license links

```bash
go-sbom -f go.mod -o sbom.yml --links
```

#### Export to JSON

```bash
go-sbom -f go.mod -o sbom.json
```

#### Override output format

```bash
go-sbom -f go.mod --format=json > sbom.json
```

Use `--format` to pick the format explicitly when writing to stdout or when the output file extension doesn't match the desired format. Accepts `text`, `csv`, `yaml`, `json`, `cyclonedx`, `spdx`, `spdx2`, or `spdx3`.

#### Set minimum license confidence

```bash
go-sbom -f go.mod --min-confidence=0.9
```

Licenses detected below the threshold are reported as `Unknown`. Defaults to `0` (accept any match).

#### How licenses are found

For each module go-sbom reads its license files from the local replace directory, the module cache, or the module proxy, and classifies their text. The license files are:

1. every top-level file with a well-known name (`LICENSE`, `LICENSE.md`, `LICENCE`, `COPYING`, `UNLICENSE`, `LICENSE-MIT`, `LICENSE-APACHE`, …, case-insensitive) or a name starting with `license`, `licence`, `copying` or `unlicense` (`LICENSE.code`, `LICENSE-APACHE-2.0.txt`, `LICENSE-THIRD-PARTY`). Licenses of documentation and logos (`LICENSE.docs`, `LICENSE-LOGO`) and source files (`license.go`) are skipped;
2. if there is none, the [REUSE](https://reuse.software/) layout, `LICENSES/*.txt`.

All licenses found, in one file or in several, are combined with `AND` (see [Enforce license policy](#enforce-license-policy)): `LICENSE` + `LICENSE.libyaml` in `gopkg.in/yaml.v2` gives `Apache-2.0 AND MIT`. Modules that use the Rust convention `LICENSE-MIT` + `LICENSE-APACHE` usually mean "either one" (`MIT OR Apache-2.0`), but the files can't say so: they are reported as `Apache-2.0 AND MIT`, which passes `--check` when both licenses are allowed. If one isn't, pin the real expression with `--licence`, or allow the missing license.

Several licenses of one module are written in the order of your `allowed` list (from the flags, `GO_SBOM_ALLOWED` or `.go-sbom.yml`, also without `--check`), then the remaining ones alphabetically; with no `allowed` list, all alphabetically. With `allowed: [MIT, Apache-2.0]`, yaml.v2 is `MIT AND Apache-2.0`. The order doesn't change the meaning (`AND` applies to all of them), it only makes the same set of licenses always read the same. Licenses set with `--licence` are kept as written.

When no license can be determined, the module is reported as `Unknown` and a warning on stderr says why: no license file, a file the classifier doesn't recognise, or a match below `--min-confidence`. Set such licenses with `--licence`.

#### Export to CycloneDX JSON

```bash
go-sbom -f go.mod -o sbom.cyclonedx.json
```

Produces a [CycloneDX](https://cyclonedx.org/) 1.7 SBOM in JSON format with Package URLs (purl) for each component. The shorter `.cdx.json` extension works too.

#### Export to SPDX JSON

```bash
go-sbom -f go.mod -o sbom.spdx.json                     # SPDX 2.3 (default)
go-sbom -f go.mod -o sbom.spdx.json --spdx-version 3    # SPDX 3.0.1
go-sbom -f go.mod -o sbom.spdx2.json                    # always SPDX 2.3 (or: --format spdx2)
```

`--format spdx` and the `.spdx.json` extension use the version from `--spdx-version` (or `spdx-version:` in the config file, or `GO_SBOM_SPDX_VERSION`): `2` for SPDX 2.3 (the default) or `3` for SPDX 3.0.1; `2.3` and `3.0.1` are accepted too. `--format spdx2`/`spdx3` and the `.spdx2.json`/`.spdx3.json` extensions always pick that version.

Produces an [SPDX](https://spdx.dev/) 2.3 SBOM in JSON format with Package URLs (purl), dependency relationships, and SPDX license identifiers.

#### Export to SPDX 3 JSON-LD

```bash
go-sbom -f go.mod -o sbom.spdx3.json      # or: --format spdx3
```

Produces an [SPDX 3.0.1](https://spdx.github.io/spdx-spec/v3.0.1/) document (JSON-LD, `core`, `software` and `simpleLicensing` profiles): one `software_Package` per module with its purl, a `dependsOn` relationship from the main module, and `hasDeclaredLicense`/`hasConcludedLicense` relationships to license expressions. Names that are not SPDX ids become `LicenseRef-` expressions with a `SimpleLicensingText`; unknown licenses are left out. SPDX 2.3 stays the default for `.spdx.json`, since many consumers do not read SPDX 3 yet.

#### Enforce license policy

```bash
go-sbom -f go.mod --check --allowed="MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC"
```

The check runs only with `--check`; it writes no SBOM. Exit code is `0` if all licenses are in the allowed list, `2` if any violations are found (`1` is used for usage and input errors).

Licenses are compared case-insensitively, and SPDX expressions are evaluated: `A AND B` needs both licenses allowed, `A OR B` needs at least one, and `A WITH exception` is allowed when `A` is (or when the whole `A WITH exception` is listed). An entry such as `Company Proprietary` is matched as a whole.

A license file can contain several licenses: `gopkg.in/yaml.v3` has MIT text for the code ported from libyaml and Apache-2.0 for the rest, and many modules append the license of vendored code. go-sbom reports every license it finds, joined with `AND` (`Apache-2.0 AND MIT`, ordered as described in [How licenses are found](#how-licenses-are-found)), because it can't tell "all of these apply" from "choose one". For a module that really is dual-licensed, set the expression with `--licence` (e.g. `--licence 'example.com/lib:MIT OR Apache-2.0'`).
`--allowed` can be given as a comma-separated list, repeated, or as a list in the config file. Without `--check` the allowed list is ignored, so it can live in `.go-sbom.yml` while normal runs keep writing SBOMs (`--allowed` given on the command line or via `GO_SBOM_ALLOWED` without `--check` prints a warning).

#### Set package licenses

```bash
go-sbom -f go.mod --licence="company.com/internal/pkg:PROPRIETARY" --licence="company.com/other:MIT"
```

Manually assign a license to a package, overriding auto-detection. Can be specified multiple times. Useful for proprietary packages or when auto-detection is incorrect. For a replaced module, use either its module path or the replacement's path (`corp.example/auth` or `./auth` for `replace corp.example/auth => ./auth`); the license is set on the replacement, which is the code that is built.

#### Exclude packages

```bash
go-sbom -f go.mod --check --allowed="MIT,Apache-2.0,BSD-3-Clause" --exclude="company.com/internal/pkg,company.com/proprietary/lib"
```

Excluded packages are skipped during license policy checks (used with `--check`) and are never fetched. Patterns use `GOPRIVATE` syntax: `company.com/internal` also matches `company.com/internal/pkg`, and globs such as `*.corp.example.com` are allowed. A replaced module is excluded when either its module path or its replacement's path matches. Output formats always include all packages; like `--allowed`, `--exclude` on the command line or in the environment without `--check` prints a warning.

#### Config file

Instead of passing flags every time, put them in `.go-sbom.yml` (or `.go-sbom.yaml`) in the current directory, or point to another file with `-c/--config`. Keys are the long flag names; list values work for `allowed`, `exclude` and `licence`:

```yaml
# .go-sbom.yml
file: go.mod
allowed:
  - MIT
  - Apache-2.0
  - BSD-2-Clause
  - BSD-3-Clause
  - ISC
exclude:
  - company.com/internal
licence:
  - company.com/proprietary/lib:LicenseRef-Company
min-confidence: 0.8
junit-file: sbom-report.xml
spdx-version: 3   # .spdx.json / --format spdx write SPDX 3.0.1 (default: 2)
```

```bash
go-sbom              # uses .go-sbom.yml, prints the SBOM
go-sbom -o sbom.csv  # flags still work and take precedence
go-sbom --check      # license check against allowed: from .go-sbom.yml
```

Precedence is: command-line flags > environment variables > config file. A missing default file is ignored, but having both `.go-sbom.yml` and `.go-sbom.yaml` is an error. A file named with `--config` must exist, and unknown keys are an error. Relative paths in the config file are relative to the current directory.

#### JUnit report for CI/CD

```bash
go-sbom -f go.mod --check --allowed="MIT,Apache-2.0,BSD-3-Clause" --junit-file=sbom-report.xml
```

The JUnit XML report is compatible with GitLab CI, Jenkins, and other CI systems. The path can also come from the `GO_SBOM_JUNIT_FILE` environment variable or `junit-file:` in the config file.

#### CGO detection

When analyzing a Go binary that was built with `CGO_ENABLED=1`, the tool prints a warning to stderr:

```
warning: binary was built with CGO_ENABLED=1; C library dependencies are not tracked in the SBOM
```

C dependencies linked via cgo are not visible to the Go module system and will not appear in the SBOM. Use `--licence` to manually add them if needed.

For a container image, the warning names the binaries built with cgo.

#### Vulnerability scanning

go-sbom does not check for known vulnerabilities. An SBOM lists components, and vulnerability data changes every day, so matching is best done by a scanner at the time you need the answer:

```bash
# source tree: reports only vulnerabilities whose code is actually called
govulncheck ./...

# built binary
govulncheck -mode binary ./app

# an SBOM written by go-sbom
go-sbom ./app -o app.cyclonedx.json
grype sbom:app.cyclonedx.json
trivy sbom app.cyclonedx.json
```

CycloneDX and SPDX files can also be uploaded to [Dependency-Track](https://dependencytrack.org/), which rechecks them as new vulnerabilities are published.

### Example output

`go-sbom go.mod` in this repository:

```
Go version:  1.27
Module:      github.com/oktalz/go-sbom
Main:        github.com/oktalz/go-sbom (MIT)

PACKAGE                                      VERSION               LICENSE
github.com/docker/cli                        v29.7.2+incompatible  Apache-2.0
github.com/google/go-containerregistry       v0.22.1               Apache-2.0
github.com/google/licenseclassifier/v2       v2.0.0                Apache-2.0
github.com/opencontainers/go-digest          v1.0.0                Apache-2.0
github.com/opencontainers/image-spec         v1.1.1                Apache-2.0
github.com/peterbourgon/ff/v4                v4.0.0-beta.1         Apache-2.0
gotest.tools/v3                              v3.5.2                Apache-2.0
github.com/oktalz/junit-report               v0.9.1                BSD-3-Clause
golang.org/x/mod                             v0.43.0               BSD-3-Clause
golang.org/x/sync                            v0.22.0               BSD-3-Clause
golang.org/x/sys                             v0.47.0               BSD-3-Clause
github.com/davecgh/go-spew                   v1.1.1                ISC
github.com/docker/docker-credential-helpers  v0.9.3                MIT
github.com/joho/godotenv                     v1.5.1                MIT
github.com/sergi/go-diff                     v1.4.0                MIT
github.com/sirupsen/logrus                   v1.9.4                MIT
gopkg.in/yaml.v2                             v2.4.0                MIT AND Apache-2.0
github.com/klauspost/compress                v1.19.2               MIT AND Apache-2.0 AND BSD-3-Clause
```

For a go.mod, `Go version` is the `go` line and the main module has no version; for a binary it is the toolchain that built it (e.g. `go1.27.4`) and the module version stamped by `go build`.

### Building

```bash
go build -o go-sbom .
```

#### Releasing

Pushing a `v*` tag runs [.github/workflows/release.yml](.github/workflows/release.yml):

```bash
git tag v0.1.0
git push origin v0.1.0
```

It runs the tests and the license check, builds the binaries with `CGO_ENABLED=0`, writes their SBOMs with go-sbom itself, validates them against the CycloneDX/SPDX schemas, attests build provenance and the SBOM, and publishes the GitHub release. Tags with a `-` (e.g. `v0.2.0-rc.1`) become pre-releases.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `GOPROXY` | Go module proxy URL(s) for fetching license files (`,` and `\|` separators, `off`) |
| `GOPRIVATE` / `GONOPROXY` | Module patterns that are never requested from a proxy |
| `GOMODCACHE` | Module cache checked for license files before downloading |
| `SOURCE_DATE_EPOCH` | Fixed timestamp for CycloneDX/SPDX output (reproducible builds) |

Every flag can also be set through an environment variable: `GO_SBOM_` followed by the long flag name in upper case, with dashes as underscores (`--min-confidence` → `GO_SBOM_MIN_CONFIDENCE`, `--junit-file` → `GO_SBOM_JUNIT_FILE`). Variables without the prefix, such as `FILE`, are ignored.

The tool also reads a `.env` file in the current directory, so these variables can be set there.

## License

[MIT](LICENSE)

The gopher mascot is in the style of the Go gopher, designed by [Renée French](https://reneefrench.blogspot.com/) and licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
