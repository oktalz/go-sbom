Fixture modules for `task sbom-validate`, which writes every SBOM format for
them and validates the output against the official schemas.

- `nodeps/` — a module without dependencies.
- `edge/` — a local `replace`, a `+incompatible` version, and (via `--licence`
  in the task) an SPDX id, an SPDX expression and a non-SPDX license name.
  All licenses are set or local, so no module is downloaded.
