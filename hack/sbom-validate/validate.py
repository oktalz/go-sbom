#!/usr/bin/env python3
"""Validate go-sbom output against the official SBOM specifications.

The check is chosen by file name:

  *.cyclonedx.json  CycloneDX 1.7 JSON schema
  *.spdx2.json      SPDX 2.3 JSON schema
  *.spdx.json       SPDX 2.3 or 3.0.1, detected from the content
  *.spdx3.json      SPDX 3.0.1 JSON schema and SHACL shapes (semantic check)

Schemas are downloaded once from pinned, versioned URLs into the cache
directory and verified by SHA-256, so a changed upstream file fails loudly
instead of silently changing what is validated.

Usage: validate.py --cache DIR FILE...
"""

import argparse
import hashlib
import json
import pathlib
import sys
import urllib.request

from jsonschema import Draft7Validator, Draft202012Validator
from referencing import Registry, Resource

CDX = "https://raw.githubusercontent.com/CycloneDX/specification/1.7.2/schema/"
SPDX3 = "https://spdx.org/"

RESOURCES = {
    "cdx/bom-1.7.schema.json": (CDX + "bom-1.7.schema.json", "73308edec3ab2d38bfffd993e96a042b594314143b6971a6e9ed98bbb6bd76ce"),
    "cdx/spdx.schema.json": (CDX + "spdx.schema.json", "4b345e2329f209f34e960ae2a8e7cb46a166907e6a45e94978565925dc47b359"),
    "cdx/jsf-0.82.schema.json": (CDX + "jsf-0.82.schema.json", "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae"),
    "cdx/cryptography-defs.schema.json": (CDX + "cryptography-defs.schema.json", "027b059a729a06d591bac79a584ef04f83fc32d91a826fdba6ad3c98a10e5b44"),
    "spdx23/spdx-schema.json": (
        "https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json",
        "239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b",
    ),
    "spdx3/schema.json": (SPDX3 + "schema/3.0.1/spdx-json-schema.json", "582c64e809d5b3ef9bd0c4de13a32391b47b0284a3e8d199569fb96f649234b1"),
    "spdx3/context.jsonld": (SPDX3 + "rdf/3.0.1/spdx-context.jsonld", "c72b0928f094c83e5c127784edb1ebca2af74a104fcacc007c332b23cbc788bd"),
    "spdx3/model.ttl": (SPDX3 + "rdf/3.0.1/spdx-model.ttl", "30ebb4af2d70a9809044ef46f44cc3dc5125226d70f818a50ed2e1d5f404c593"),
}


def fetch(cache: pathlib.Path, name: str) -> pathlib.Path:
    url, want = RESOURCES[name]
    path = cache / name
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 (pinned https URLs)
            path.write_bytes(resp.read())
    got = hashlib.sha256(path.read_bytes()).hexdigest()
    if got != want:
        path.unlink()
        sys.exit(f"error: {url} has sha256 {got}, expected {want}")
    return path


def schema_errors(validator, doc) -> list[str]:
    errors = []
    for err in validator.iter_errors(doc):
        # oneOf/anyOf errors hide the useful message in their context.
        best = err
        while best.context:
            best = max(best.context, key=lambda e: len(list(e.absolute_path)))
        path = "/".join(str(p) for p in best.absolute_path) or "(root)"
        errors.append(f"{path}: {best.message[:300]}")
    return errors


class Validators:
    def __init__(self, cache: pathlib.Path):
        self.cache = cache
        self._cdx = self._spdx23 = self._spdx3 = self._shapes = self._context = None

    def cyclonedx(self, doc) -> list[str]:
        if self._cdx is None:
            registry = Registry()
            for name in RESOURCES:
                if name.startswith("cdx/"):
                    schema = json.loads(fetch(self.cache, name).read_text())
                    registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
                    registry = registry.with_resource(pathlib.Path(name).name, Resource.from_contents(schema))
            root = json.loads(fetch(self.cache, "cdx/bom-1.7.schema.json").read_text())
            self._cdx = Draft7Validator(root, registry=registry)
        return schema_errors(self._cdx, doc)

    def spdx23(self, doc) -> list[str]:
        if self._spdx23 is None:
            self._spdx23 = Draft7Validator(json.loads(fetch(self.cache, "spdx23/spdx-schema.json").read_text()))
        return schema_errors(self._spdx23, doc)

    def spdx3(self, doc) -> list[str]:
        if self._spdx3 is None:
            self._spdx3 = Draft202012Validator(json.loads(fetch(self.cache, "spdx3/schema.json").read_text()))
        errors = schema_errors(self._spdx3, doc)
        return errors + self._spdx3_shacl(doc)

    def _spdx3_shacl(self, doc) -> list[str]:
        import pyshacl
        import rdflib

        if self._shapes is None:
            self._shapes = rdflib.Graph().parse(fetch(self.cache, "spdx3/model.ttl"), format="turtle")
            self._context = json.loads(fetch(self.cache, "spdx3/context.jsonld").read_text())["@context"]
        local = dict(doc)
        local["@context"] = self._context  # pinned copy of the 3.0.1 context, no network
        graph = rdflib.Graph().parse(data=json.dumps(local), format="json-ld")
        conforms, _, text = pyshacl.validate(
            graph, shacl_graph=self._shapes, ont_graph=self._shapes, inference="none", abort_on_first=False
        )
        if conforms:
            return []
        return ["SHACL: " + line.strip() for line in text.splitlines() if "Message:" in line]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cache", required=True, type=pathlib.Path, help="directory for downloaded schemas")
    parser.add_argument("files", nargs="+", type=pathlib.Path)
    args = parser.parse_args()

    validators = Validators(args.cache)
    failed = 0
    for path in args.files:
        name = path.name.lower()
        if name.endswith(".cyclonedx.json"):
            kind, check = "CycloneDX 1.7", validators.cyclonedx
        elif name.endswith(".spdx3.json"):
            kind, check = "SPDX 3.0.1", validators.spdx3
        elif name.endswith((".spdx2.json", ".spdx.json")):
            kind, check = "SPDX 2.3", validators.spdx23
        else:
            print(f"{path}: skipped (unknown format)")
            continue
        doc = json.loads(path.read_text())
        if name.endswith(".spdx.json") and "@context" in doc:
            kind, check = "SPDX 3.0.1", validators.spdx3
        errors = check(doc)
        print(f"{path}: {kind} {'ok' if not errors else f'{len(errors)} error(s)'}")
        for err in errors[:10]:
            print(f"    {err}")
        failed += bool(errors)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
