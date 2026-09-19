# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Package URL construction and parsing, enough of it for embedded Linux.

A purl is what makes a VEX statement machine-actionable. Emitting
``pkg:generic/busybox@1.36.1`` when the world calls it
``pkg:openembedded/busybox@1.36.1`` means downstream scanners silently fail to
match. Getting the type right is most of the value here.

Spec: https://github.com/package-url/purl-spec
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import quote, unquote

_PURL = re.compile(
    r"^pkg:(?P<type>[^/]+)/(?P<rest>[^?#]+)(\?(?P<qualifiers>[^#]*))?(#(?P<subpath>.*))?$"
)

#: Origin string emitted by an ingester -> purl type.
ORIGIN_TYPES = {
    "yocto": "generic",
    "buildroot": "generic",
    "cyclonedx": None,  # the SBOM already carries one
    "spdx": None,
    "deb": "deb",
    "rpm": "rpm",
    "apk": "apk",
}


@dataclass
class PackageURL:
    type: str
    name: str
    namespace: str | None = None
    version: str | None = None
    qualifiers: dict[str, str] = field(default_factory=dict)
    subpath: str | None = None

    def __str__(self) -> str:
        out = f"pkg:{self.type}"
        if self.namespace:
            out += "/" + quote(self.namespace, safe="")
        out += "/" + quote(self.name, safe="")
        if self.version:
            out += "@" + quote(self.version, safe="")
        if self.qualifiers:
            pairs = "&".join(
                f"{k}={quote(v, safe='')}" for k, v in sorted(self.qualifiers.items()) if v
            )
            if pairs:
                out += "?" + pairs
        if self.subpath:
            out += "#" + self.subpath
        return out


def parse(value: str) -> PackageURL | None:
    """Parse a purl string. Returns ``None`` rather than raising on junk."""
    if not value:
        return None
    m = _PURL.match(value.strip())
    if not m:
        return None
    rest = m.group("rest")
    version = None
    if "@" in rest:
        rest, _, version = rest.rpartition("@")
        version = unquote(version)
    parts = [unquote(p) for p in rest.split("/") if p]
    if not parts:
        return None
    name = parts[-1]
    namespace = "/".join(parts[:-1]) or None
    qualifiers = {}
    if m.group("qualifiers"):
        for pair in m.group("qualifiers").split("&"):
            if "=" in pair:
                k, _, val = pair.partition("=")
                qualifiers[k] = unquote(val)
    return PackageURL(
        type=m.group("type").lower(),
        name=name,
        namespace=namespace,
        version=version,
        qualifiers=qualifiers,
        subpath=m.group("subpath") or None,
    )


def for_component(
    name: str, version: str, origin: str = "", arch: str = "", distro: str = ""
) -> str:
    """Build a purl for a component read out of a build tree.

    ``pkg:generic`` is used for Yocto and Buildroot recipes. That is deliberate:
    there is no registered purl type for either, and inventing
    ``pkg:openembedded`` would produce identifiers no scanner resolves. Build
    provenance goes in qualifiers instead, where it is readable but does not
    break matching.
    """
    base = (origin or "").split(":", 1)[0].lower()
    ptype = ORIGIN_TYPES.get(base) or "generic"
    qualifiers: dict[str, str] = {}
    if arch:
        qualifiers["arch"] = arch
    if distro:
        qualifiers["distro"] = distro
    if base in ("yocto", "buildroot"):
        qualifiers["build_system"] = base
    return str(
        PackageURL(type=ptype, name=name, version=version or None, qualifiers=qualifiers)
    )


def same_package(a: str | None, b: str | None) -> bool:
    """Do two purls name the same package, ignoring version and qualifiers?"""
    pa, pb = parse(a or ""), parse(b or "")
    if not pa or not pb:
        return False
    return (pa.type, pa.namespace, pa.name) == (pb.type, pb.namespace, pb.name)
