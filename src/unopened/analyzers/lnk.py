"""Windows shortcut (LNK) analysis with LnkParse3.

Reports what the shortcut would launch, flags LOLBin targets, encoded or padded command
lines and borrowed icons, and pulls the creator's machine name and MAC address from the
tracker block. Encoded commands are decoded as text for display only.
"""

from __future__ import annotations

import io
import re
import struct
import tomllib
import uuid
from functools import cache
from importlib import resources
from typing import Any

from ..deobfuscate import find_encoded_command
from ..model import AnalyzerOutput, Finding, Severity
from . import Context

BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
HIDDEN_WINDOW_RE = re.compile(r"(?i)[-/]w(?:indowstyle)?\s+(?:hidden|h\b|1\b)")
WHITESPACE_RUN = re.compile(r"\s{50,}")
MAX_DISPLAY = 2000
LONG_ARGS = 260
MINIMIZED_STYLES = {"SW_SHOWMINNOACTIVE", "SW_SHOWMINIMIZED", "SW_MINIMIZE", "SW_HIDE"}


@cache
def lolbins() -> dict[str, dict[str, Any]]:
    text = resources.files("unopened").joinpath("data/lolbins.toml").read_text("utf-8")
    table = tomllib.loads(text)
    return {name.lower(): {**entry, "group": key}
            for key, entry in table.items() for name in entry["names"]}


def _basename(path: str) -> str:
    return re.split(r"[\\/]", path.strip().strip('"'))[-1].lower()


def _target(j: dict[str, Any]) -> str:
    info = j.get("link_info") or {}
    if info.get("local_base_path"):
        return info["local_base_path"] + (info.get("common_path_suffix") or "")
    net = (info.get("common_network_relative_link") or {}).get("net_name")
    if net:
        return net + "\\" + (info.get("common_path_suffix") or "")
    extra = j.get("extra") or {}
    # Windows' own Start-menu shortcuts often keep the target only here, as a path with
    # environment variables (%windir%\\system32\\charmap.exe). M5 corpus 2: 17 of them.
    env = extra.get("ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK") or {}
    expanded = _clean(env.get("target_unicode")) or _clean(env.get("target_ansi"))
    if expanded:
        return expanded
    data = j.get("data") or {}
    if data.get("relative_path"):
        return data["relative_path"]
    items = (j.get("target") or {}).get("items") or []
    names = [i.get("primary_name") or i.get("data") for i in items if isinstance(i, dict)]
    joined = "\\".join(str(n) for n in names if n)
    if joined:
        return joined
    # Windows Installer "advertised" shortcut: names an installed product, not a path.
    darwin = extra.get("DARWIN_BLOCK") or {}
    product = _clean(darwin.get("darwin_data_unicode")) or _clean(darwin.get("darwin_data_ansi"))
    return f"[Windows Installer advertised shortcut: {product}]" if product else ""


def _clean(value: Any) -> str:
    return str(value).split("\0", 1)[0].strip() if value else ""


def _mac_from_droid(droid: str | None) -> str | None:
    try:
        u = uuid.UUID(droid) if droid else None
    except ValueError:
        return None
    if u is None or u.version != 1:
        return None
    node = f"{u.node:012x}"
    return ":".join(node[i:i + 2] for i in range(0, 12, 2))


def analyze_lnk(ctx: Context) -> AnalyzerOutput:
    import LnkParse3

    data = ctx.path.read_bytes()
    parsed = LnkParse3.lnk_file(io.BytesIO(data))
    j = parsed.get_json()
    header = j.get("header") or {}
    strings = j.get("data") or {}
    tracker = (j.get("extra") or {}).get("DISTRIBUTED_LINK_TRACKER_BLOCK") or {}

    target = _target(j)
    args = strings.get("command_line_arguments") or ""
    info: dict[str, Any] = {
        "target": target,
        "arguments": args[:MAX_DISPLAY],
        "arguments_length": len(args),
        "working_directory": strings.get("working_directory"),
        "relative_path": strings.get("relative_path"),
        "icon_location": strings.get("icon_location"),
        "description": strings.get("description"),
        "window_style": header.get("windowstyle"),
        "machine_id": tracker.get("machine_identifier") or None,
        "mac_address": _mac_from_droid(tracker.get("droid_file_identifier")),
        "structure_size": structure_end(data),
        "file_size": len(data),
    }
    out = AnalyzerOutput(data={"shortcut": info})
    texts = [t for t in (target, args, info["working_directory"], info["relative_path"],
                         info["icon_location"], info["description"]) if t]
    _check_target(info, out)
    decoded = _check_arguments(info, args, out)
    texts += decoded
    _check_appended(info, data, out)
    if not target:
        out.errors.append("could not determine the shortcut target")

    out.data["indicator_texts"] = [["lnk", t] for t in texts]
    direct = []
    if info["machine_id"]:
        direct.append({"kind": "hostname", "value": info["machine_id"],
                       "tags": ["lnk_creator_machine"]})
    if info["mac_address"]:
        direct.append({"kind": "mac_address", "value": info["mac_address"],
                       "tags": ["lnk_creator_machine"]})
    out.data["direct_indicators"] = direct
    return out


def _check_target(info: dict[str, Any], out: AnalyzerOutput) -> None:
    name = _basename(info["target"]) if info["target"] else ""
    entry = lolbins().get(name)
    if entry:
        out.findings.append(Finding(
            "lnk.lolbin_target",
            Severity(entry["severity"]), f"Shortcut launches {name}",
            f"{entry['why']} Shortcuts delivered by email or download rarely have a good "
            "reason to start this program.",
        ))
        icon = info["icon_location"]
        if icon and _basename(icon) != name:
            out.findings.append(Finding(
                "lnk.borrowed_icon",
                Severity.MEDIUM, "Shortcut borrows another program's icon",
                f"It launches {name} but shows the icon of {_basename(icon)}, so it looks "
                "like a different kind of file.",
            ))
    if info["target"].startswith("\\\\"):
        out.findings.append(Finding(
            "lnk.network_target",
            Severity.MEDIUM, "Shortcut points to a network location",
            "The target lives on a remote share, which can also leak Windows credentials "
            "to that server when the shortcut is opened.",
        ))
    if info["window_style"] in MINIMIZED_STYLES:
        out.findings.append(Finding(
            "lnk.minimized",
            Severity.LOW, "Shortcut starts its program minimized",
            "Used to keep a console window from being noticed.",
        ))


def _check_arguments(info: dict[str, Any], args: str, out: AnalyzerOutput) -> list[str]:
    decoded_texts = []
    if not args:
        return decoded_texts
    lowered = args.lower()
    for name, entry in lolbins().items():
        stem = name.removesuffix(".exe")
        if re.search(rf"(?<![\w.-]){re.escape(stem)}(?:\.exe)?(?![\w-])", lowered) \
                and name != _basename(info["target"] or ""):
            out.findings.append(Finding(
                "lnk.lolbin_argument",
                Severity(entry["severity"]), f"Arguments start {name}",
                f"{entry['why']} The shortcut hands this program its command.",
            ))
            break
    found = find_encoded_command(args)
    if found:
        text = found[1]
        detail = (f"Decoded (shown as text, not run): {text[:500]}" if text
                  else "The encoded value could not be decoded as text.")
        out.findings.append(Finding(
            "lnk.encoded_powershell",
            Severity.HIGH, "Encoded PowerShell command",
            "The command is base64-encoded so that it cannot be read at a glance. " + detail,
        ))
        if text:
            info["decoded_command"] = text[:MAX_DISPLAY]
            decoded_texts.append(text)
    elif BASE64_BLOB_RE.search(args):
        out.findings.append(Finding(
            "lnk.base64_blob",
            Severity.MEDIUM, "Long base64-like value in the arguments",
            "Often an encoded payload or command.",
        ))
    if HIDDEN_WINDOW_RE.search(args):
        out.findings.append(Finding(
            "lnk.hidden_window",
            Severity.MEDIUM, "Command asks for a hidden window",
            "The program is told to run without showing a window.",
        ))
    if len(args) > LONG_ARGS or WHITESPACE_RUN.search(args):
        out.findings.append(Finding(
            "lnk.padded_arguments",
            Severity.MEDIUM, f"Very long or whitespace-padded arguments ({len(args):,} chars)",
            "Windows shows only the first 260 characters in the shortcut's Properties, so "
            "padding pushes the real command out of view.",
        ))
        info["arguments_compact"] = re.sub(r"\s{2,}", " ", args).strip()[:MAX_DISPLAY]
    return decoded_texts


def structure_end(data: bytes) -> int | None:
    """Offset just past the terminal extra-data block, walking MS-SHLLINK structures."""
    try:
        flags = struct.unpack_from("<I", data, 0x14)[0]
        pos = 0x4C
        if flags & 0x01:  # HasLinkTargetIDList
            pos += 2 + struct.unpack_from("<H", data, pos)[0]
        if flags & 0x02 and not flags & 0x100:  # HasLinkInfo, not ForceNoLinkInfo
            pos += struct.unpack_from("<I", data, pos)[0]
        width = 2 if flags & 0x80 else 1
        for bit in (0x04, 0x08, 0x10, 0x20, 0x40):  # name, path, dir, args, icon
            if flags & bit:
                pos += 2 + width * struct.unpack_from("<H", data, pos)[0]
        while True:
            size = struct.unpack_from("<I", data, pos)[0]
            if size < 4:
                return pos + 4
            pos += size
            if pos > len(data):
                return None
    except struct.error:
        return None


def _check_appended(info: dict[str, Any], data: bytes, out: AnalyzerOutput) -> None:
    end = info["structure_size"]
    if end is None:
        out.errors.append("could not walk the shortcut structure to its end")
        return
    if end >= len(data):
        return
    extra = data[end:]
    if not extra.strip(b"\0"):
        return
    info["appended_bytes"] = len(extra)
    embedded_pe = extra[:2] == b"MZ"
    out.findings.append(Finding(
        "lnk.appended_pe" if embedded_pe else "lnk.appended_data",
        Severity.HIGH if embedded_pe else Severity.MEDIUM,
        f"Data appended after the shortcut ({len(extra):,} bytes)",
        ("It starts with an MZ header, so a program is probably hidden inside. "
         if embedded_pe else "")
        + "Some malicious shortcuts carry their payload here and extract it with the command "
        "line.",
    ))
    out.not_checked.append(f"Content appended to the shortcut ({len(extra):,} bytes)")
