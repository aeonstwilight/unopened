"""Editable allowlist of known-benign indicator noise (see data/allowlist.toml)."""

from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from urllib.parse import urlsplit

KNOWN_SECTIONS = {"domains", "urls", "ips", "emails", "paths", "registry"}


class AllowlistError(ValueError):
    pass


@dataclass
class Allowlist:
    source: str = "empty"
    domains_exact: set[str] = field(default_factory=set)
    domains_suffix: set[str] = field(default_factory=set)
    url_prefixes: list[str] = field(default_factory=list)
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    emails_exact: set[str] = field(default_factory=set)
    path_prefixes: list[str] = field(default_factory=list)
    registry_prefixes: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path | None = None) -> Allowlist:
        """Load the given allowlist file, or the default shipped with the package."""
        if path is None:
            text = resources.files("unopened").joinpath("data/allowlist.toml").read_text("utf-8")
            source = "built-in default"
        else:
            try:
                text = path.read_text(encoding="utf-8")
            except OSError as exc:
                raise AllowlistError(f"cannot read allowlist {path}: {exc}") from exc
            source = str(path)
        try:
            doc = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise AllowlistError(f"allowlist {source} is not valid TOML: {exc}") from exc
        return cls.from_dict(doc, source)

    @classmethod
    def from_dict(cls, doc: dict, source: str = "inline") -> Allowlist:
        unknown = set(doc) - KNOWN_SECTIONS
        if unknown:
            raise AllowlistError(
                f"allowlist {source}: unknown section(s) {sorted(unknown)}; "
                f"expected {sorted(KNOWN_SECTIONS)}"
            )

        def strings(section: str, key: str) -> list[str]:
            value = doc.get(section, {}).get(key, [])
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise AllowlistError(
                    f"allowlist {source}: [{section}] {key} must be a list of strings"
                )
            return [v.strip() for v in value if v.strip()]

        networks = []
        for entry in strings("ips", "cidr"):
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError as exc:
                raise AllowlistError(f"allowlist {source}: bad IP/CIDR {entry!r}: {exc}") from exc
        return cls(
            source=source,
            domains_exact={d.lower().rstrip(".") for d in strings("domains", "exact")},
            domains_suffix={d.lower().strip(".") for d in strings("domains", "suffix")},
            url_prefixes=[u.lower() for u in strings("urls", "prefix")],
            networks=networks,
            emails_exact={e.lower() for e in strings("emails", "exact")},
            path_prefixes=[p.lower() for p in strings("paths", "prefix")],
            registry_prefixes=[r.lower() for r in strings("registry", "prefix")],
        )

    def domain_allowed(self, domain: str) -> bool:
        domain = domain.lower().rstrip(".")
        if domain in self.domains_exact:
            return True
        return any(domain == s or domain.endswith("." + s) for s in self.domains_suffix)

    def ip_allowed(self, value: str) -> bool:
        try:
            ip = ipaddress.ip_address(value.strip("[]"))
        except ValueError:
            return False
        return any(ip.version == n.version and ip in n for n in self.networks)

    def allows(self, kind: str, value: str) -> bool:
        lowered = value.lower()
        if kind == "domain":
            return self.domain_allowed(value)
        if kind in ("ipv4", "ipv6"):
            return self.ip_allowed(value)
        if kind == "url":
            if any(lowered.startswith(p) for p in self.url_prefixes):
                return True
            try:
                host = urlsplit(value).hostname or ""
            except ValueError:
                return False
            return self.domain_allowed(host) or self.ip_allowed(host)
        if kind == "email":
            return lowered in self.emails_exact or self.domain_allowed(lowered.rpartition("@")[2])
        if kind in ("file_path", "unc_path"):
            return any(lowered.startswith(p) for p in self.path_prefixes)
        if kind == "registry_key":
            return any(lowered.startswith(p) for p in self.registry_prefixes)
        return False
