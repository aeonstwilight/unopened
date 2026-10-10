"""Archives and disk images: ZIP (including ZipCrypto/AES with a known password), 7z and
ISO 9660/Joliet/Rock Ridge/UDF.

Members are extracted with unopened.extraction (bounded, index-named, private temp
directory). The pipeline then triages each extracted member recursively. Nothing in an
archive is ever opened by the operating system or run.
"""

from __future__ import annotations

import zipfile
import zlib
from typing import Any

from ..extraction import CHUNK, LimitHit, MemberWriter
from ..identify import RUNNABLE
from ..model import AnalyzerOutput, Finding, Severity
from . import AnalyzerUnavailable, Context

MAX_LISTED = 5000  # metadata entries kept per archive; the rest are counted


def analyze_archive(ctx: Context) -> AnalyzerOutput:
    out = AnalyzerOutput()
    writer = MemberWriter(ctx.extract_dir, ctx.options.limits, ctx.files_left, ctx.bytes_left)
    out.data = {"format": ctx.file_type.kind, "passwords_tried": [], "password_used": None,
                "unlisted_members": 0}
    if ctx.file_type.kind == "zip":
        _zip(ctx, writer, out)
    elif ctx.file_type.kind == "7z":
        _sevenzip(ctx, writer, out)
    elif ctx.file_type.kind == "iso":
        _iso(ctx, writer, out)
    out.data.update({
        "members": writer.members,
        "extracted_files": writer.used_files,
        "extracted_bytes": writer.used_bytes,
        "stopped": writer.stopped,
        "depth_limited": ctx.extract_dir is None,
    })
    _findings(ctx, writer, out)
    return out


def _passwords(ctx: Context) -> list[str]:
    return list(dict.fromkeys(ctx.options.archive_passwords))


# ZIP -----------------------------------------------------------------------------------

def _zip(ctx: Context, w: MemberWriter, out: AnalyzerOutput) -> None:
    try:
        import pyzipper

        opener: Any = pyzipper.AESZipFile
    except ImportError:
        opener = zipfile.ZipFile
        out.not_checked.append("AES-encrypted ZIP members (pyzipper not installed)")
    passwords = _passwords(ctx)
    with opener(ctx.path) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        out.data["member_count"] = len(infos)
        for n, info in enumerate(infos):
            if n >= MAX_LISTED:
                out.data["unlisted_members"] = len(infos) - MAX_LISTED
                out.not_checked.append(f"{len(infos) - MAX_LISTED:,} members beyond the first "
                                       f"{MAX_LISTED:,} were not listed or extracted")
                break
            encrypted = bool(info.flag_bits & 0x1)
            aes = getattr(info, "compress_type", 0) == 99
            sink = w.open(info.filename, info.file_size, info.compress_size,
                          encrypted=encrypted, encryption="AES" if aes else
                          ("ZipCrypto" if encrypted else None))
            if sink is None:
                continue
            try:
                with sink:
                    if not encrypted:
                        with zf.open(info) as stream:
                            _copy(stream, sink)
                        continue
                    if not _decrypt_zip_member(zf, info, passwords, sink, out):
                        sink.fail(f"encrypted; none of the {len(passwords)} password(s) worked")
                        sink.entry["password_unknown"] = True
            except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, EOFError,
                    zlib.error, ValueError) as exc:
                out.errors.append(f"member {info.filename}: {type(exc).__name__}: {exc}")


def _copy(stream: Any, sink: Any) -> None:
    while chunk := stream.read(CHUNK):
        sink.write(chunk)


def _decrypt_zip_member(zf: Any, info: Any, passwords: list[str], sink: Any,
                        out: AnalyzerOutput) -> bool:
    """Try each password. ZipCrypto's one-byte check accepts a wrong password about one time
    in 256, so a password only counts once the member decrypts with a good CRC."""
    ordered = ([out.data["password_used"]] if out.data["password_used"] else []) + passwords
    for pw in dict.fromkeys(ordered):
        if pw not in out.data["passwords_tried"]:
            out.data["passwords_tried"].append(pw)
        try:
            with zf.open(info, pwd=pw.encode()) as stream:
                _copy(stream, sink)
        except RuntimeError as exc:
            if "password" in str(exc).lower():
                continue
            raise
        except (zipfile.BadZipFile, zlib.error) as exc:
            if "crc" in str(exc).lower() or isinstance(exc, zlib.error):
                sink.reset()  # wrong password that slipped past the check byte
                continue
            raise
        out.data["password_used"] = pw
        return True
    return False


# 7z ------------------------------------------------------------------------------------

class _SevenZipSink:
    """py7zr writer adapter: bytes go straight through the bounded sink."""

    def __init__(self, sink: Any):
        self.sink = sink
        self.closed = False

    def write(self, data: bytes) -> int:
        return self.sink.write(bytes(data))

    def read(self, size: int | None = None) -> bytes:
        return b""

    def seek(self, offset: int, whence: int = 0) -> int:
        return 0

    def flush(self) -> None:
        return None

    def size(self) -> int:
        return self.sink.written

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self.sink.__exit__(None, None, None)


def _sevenzip(ctx: Context, w: MemberWriter, out: AnalyzerOutput) -> None:
    try:
        import py7zr
        from py7zr.io import WriterFactory
    except ImportError as exc:
        raise AnalyzerUnavailable(
            "py7zr is not installed; install with: pip install 'unopened[archive]'"
        ) from exc

    candidates: list[str | None] = [None, *_passwords(ctx)]
    archive = None
    for pw in candidates:
        try:
            archive = py7zr.SevenZipFile(ctx.path, password=pw)
            break
        except (py7zr.exceptions.PasswordRequired, py7zr.exceptions.Bad7zFile, ValueError,
                OSError, KeyError) as exc:
            if pw is not None:
                out.data["passwords_tried"].append(pw)
            last = exc
    if archive is None:
        out.data["header_encrypted"] = True
        raise ValueError(f"cannot open 7z archive (encrypted headers, no password worked?): "
                         f"{last}")
    try:
        infos = [i for i in archive.list() if not i.is_directory]
        out.data["member_count"] = len(infos)
        needs_password = archive.needs_password()
        out.data["encrypted"] = needs_password
        wanted: dict[str, Any] = {}
        for info in infos[:MAX_LISTED]:
            reason = w.check_declared(info.uncompressed, info.compressed)
            if reason:
                w.record(info.filename, info.uncompressed, skipped=reason,
                         compressed=info.compressed, encrypted=needs_password)
            else:
                wanted[info.filename] = info
        if len(infos) > MAX_LISTED:
            out.data["unlisted_members"] = len(infos) - MAX_LISTED
            out.not_checked.append(f"{len(infos) - MAX_LISTED:,} members beyond the first "
                                   f"{MAX_LISTED:,} were not listed or extracted")
    finally:
        archive.close()
    if not wanted:
        return

    tries: list[str | None] = [None] if not needs_password else _passwords(ctx)
    for pw in tries:
        if pw is not None and pw not in out.data["passwords_tried"]:
            out.data["passwords_tried"].append(pw)
        start = len(w.members)
        sinks: list[_SevenZipSink] = []
        factory = _factory(WriterFactory, w, wanted, needs_password, sinks)
        try:
            with py7zr.SevenZipFile(ctx.path, password=pw,
                                    max_extract_size=max(w.bytes_left - w.used_bytes, 1)) as a:
                a.extract(targets=list(wanted), factory=factory)
            for s in sinks:
                s.close()
            if pw is not None:
                out.data["password_used"] = pw
            return
        except LimitHit as exc:
            for s in sinks:
                if not s.closed:
                    s.closed = True
                    s.sink.__exit__(LimitHit, exc, None)
            out.errors.append(f"7z extraction stopped: {exc}")
            return
        except Exception as exc:
            # Wrong password (CRC/decompression error) or a damaged archive: undo this try.
            for s in sinks:
                if not s.closed:
                    s.closed = True
                    s.sink.fail("extraction failed")
                    s.sink.__exit__(None, None, None)
            if needs_password and pw != tries[-1]:
                _rollback(w, start)
                continue
            if needs_password:
                _rollback(w, start)
                for name, info in wanted.items():
                    w.record(name, info.uncompressed, compressed=info.compressed,
                             skipped=f"not extracted: encrypted; none of the {len(tries)} "
                                     "password(s) worked", encrypted=True, password_unknown=True)
                return
            out.errors.append(f"7z extraction failed: {type(exc).__name__}: {exc}")
            return


def _factory(base: Any, w: MemberWriter, wanted: dict[str, Any], encrypted: bool,
             sinks: list[_SevenZipSink]) -> Any:
    """A py7zr WriterFactory that routes every member through the bounded writer."""
    from py7zr.io import NullIO

    class Factory(base):
        def create(self, filename: str) -> Any:
            info = wanted.get(filename)
            size = info.uncompressed if info else None
            comp = info.compressed if info else None
            sink = w.open(filename, size, comp, encrypted=encrypted)
            if sink is None:
                return NullIO()
            adapter = _SevenZipSink(sink)
            sinks.append(adapter)
            return adapter

    return Factory()


def _rollback(w: MemberWriter, start: int) -> None:
    for entry in w.members[start:]:
        if entry.get("stored") and w.directory is not None:
            (w.directory / entry["stored"]).unlink(missing_ok=True)
            w.used_files -= 1
            w.used_bytes -= entry["size"] or 0
    del w.members[start:]


# ISO -----------------------------------------------------------------------------------

def _iso(ctx: Context, w: MemberWriter, out: AnalyzerOutput) -> None:
    try:
        import pycdlib
    except ImportError as exc:
        raise AnalyzerUnavailable(
            "pycdlib is not installed; install with: pip install 'unopened[archive]'"
        ) from exc

    iso = pycdlib.PyCdlib()
    iso.open(str(ctx.path))
    try:
        if iso.has_joliet():
            key = "joliet_path"
        elif iso.has_rock_ridge():
            key = "rr_path"
        elif iso.has_udf():
            key = "udf_path"
        else:
            key = "iso_path"
        out.data["filesystem"] = {"joliet_path": "Joliet", "rr_path": "Rock Ridge",
                                  "udf_path": "UDF", "iso_path": "ISO 9660"}[key]
        count = 0
        for dirpath, _dirs, files in iso.walk(**{key: "/"}):
            for fname in files:
                count += 1
                if count > MAX_LISTED:
                    continue
                full = dirpath.rstrip("/") + "/" + fname
                display = full.lstrip("/")
                if key == "iso_path":
                    display = display.split(";")[0]
                try:
                    rec = iso.get_record(**{key: full})
                    size = rec.get_data_length()
                    flags = getattr(rec, "file_flags", 0) or 0
                    hidden = bool(flags & 0x1)
                except Exception as exc:
                    out.errors.append(f"{display}: {type(exc).__name__}: {exc}")
                    continue
                sink = w.open(display, size, None, hidden=hidden)
                if sink is None:
                    continue
                try:
                    with sink:
                        iso.get_file_from_iso_fp(sink, **{key: full})
                except Exception as exc:
                    out.errors.append(f"{display}: {type(exc).__name__}: {exc}")
        out.data["member_count"] = count
        if count > MAX_LISTED:
            out.data["unlisted_members"] = count - MAX_LISTED
            out.not_checked.append(f"{count - MAX_LISTED:,} files beyond the first "
                                   f"{MAX_LISTED:,} were not listed or extracted")
        if key == "udf_path":
            out.not_checked.append("Hidden-file flags in a UDF-only image")
    finally:
        iso.close()


# Findings ------------------------------------------------------------------------------

def _findings(ctx: Context, w: MemberWriter, out: AnalyzerOutput) -> None:
    members = w.members
    traversal = [m["name"] for m in members
                 if {"path_traversal", "absolute_path"} & set(m["flags"])]
    if traversal:
        out.findings.append(Finding(
            "archive.path_traversal", Severity.HIGH, "Member names try to escape the folder",
            f"{', '.join(traversal[:5])}. Vulnerable extraction tools would write these "
            "outside the destination folder (they were safely renamed here).",
        ))
    tricky = [m["name"] for m in members if {"direction_override", "nul_in_name"} & set(m["flags"])]
    if tricky:
        out.findings.append(Finding(
            "archive.deceptive_names", Severity.HIGH, "Member names use display tricks",
            f"{', '.join(repr(t) for t in tricky[:5])}: Unicode direction overrides or NUL "
            "characters make a name display differently from what it is.",
        ))
    unknown_pw = [m["name"] for m in members if m.get("password_unknown")]
    if unknown_pw:
        out.findings.append(Finding(
            "archive.password_unknown", Severity.MEDIUM,
            f"{len(unknown_pw)} encrypted member(s) could not be opened",
            "None of the configured passwords worked, so their contents were not analyzed. "
            "Malware is often sent in password-protected archives to get past mail filters; "
            "add the password from the email with --archive-password.",
        ))
        out.not_checked.append(f"{len(unknown_pw)} encrypted member(s) with an unknown password")
    if out.data.get("password_used"):
        out.findings.append(Finding(
            "archive.password_protected", Severity.LOW,
            "Archive is password-protected",
            f"Opened with the password {out.data['password_used']!r}. Password protection "
            "hides the contents from mail and web filters.",
        ))
    if w.stopped:
        out.findings.append(Finding(
            "archive.limit_hit", Severity.MEDIUM, "Extraction stopped at a safety limit",
            f"{w.stopped}. Some members were not analyzed. An archive that hits these limits "
            "may be a decompression bomb.",
        ))
    bomb = [m for m in members if (m.get("skipped") or "").find("zip bomb") >= 0]
    if bomb:
        out.findings.append(Finding(
            "archive.bomb", Severity.MEDIUM, "Members look like a decompression bomb",
            f"{len(bomb)} member(s) expand far more than normal data does; they were not "
            "extracted.",
        ))
    pumped = _pumped(members, ctx)
    if pumped:
        out.findings.append(Finding(
            "archive.pumped_member", Severity.HIGH,
            f"Program inflated past analysis size limits ({len(pumped)})",
            f"{', '.join(pumped[:3])}. A program that declares far more bytes than its "
            "compressed data would normally hold has been padded (file pumping), a technique "
            "for slipping past antivirus and sandbox size limits. It was not extracted; the "
            "padding itself is the evidence.",
        ))
    skipped = [m for m in members if m.get("skipped")]
    if skipped:
        reasons = sorted({m["skipped"] for m in skipped})
        out.not_checked.append(
            f"{len(skipped)} member(s) not extracted ({'; '.join(reasons[:3])})"
        )
    if ctx.extract_dir is None and members:
        out.findings.append(Finding(
            "archive.depth_limit", Severity.LOW, "Nested too deeply to extract",
            f"This archive sits at the nesting depth limit ({ctx.options.limits.max_depth}); "
            "its members are listed but not analyzed. Deep nesting is itself an evasion trick.",
        ))
    hidden = [m["name"] for m in members if m.get("hidden")]
    if hidden:
        out.findings.append(Finding(
            "archive.hidden_files", Severity.MEDIUM, f"Hidden files in the image ({len(hidden)})",
            f"{', '.join(hidden[:5])}. Windows Explorer will not show these when the image "
            "is mounted, a trick used to show only a shortcut while hiding the payload.",
        ))
    if ctx.file_type.kind in ("iso", "7z"):
        out.findings.append(Finding(
            "archive.motw", Severity.INFO, "Container can strip the Mark of the Web",
            "Files inside ISO images (and 7z archives extracted with some tools) do not carry "
            "the downloaded-from-internet flag, so Windows skips some security prompts. This "
            "is why attackers deliver payloads this way.",
        ))


PUMP_RATIO = 20  # legitimate large programs compress 2-3x; the M5 holdout sample was ~64x


def _pumped(members: list[dict[str, Any]], ctx: Context) -> list[str]:
    """Runnable members skipped for declaring more than the per-member limit, with a
    declared size far beyond their compressed data. M5 holdout: a 15 MB 7z declared a
    961 MB program and was reported only as "could not analyze"."""
    limit = ctx.options.limits.max_member_size
    out = []
    for m in members:
        size = m.get("size") or 0
        ext = m["name"].rsplit(".", 1)[-1].lower() if "." in m["name"] else ""
        over = "per-member limit" in (m.get("skipped") or "")
        if size <= limit or ext not in RUNNABLE or not over:
            continue
        compressed = m.get("compressed_size") or ctx.size  # solid 7z: no per-member size
        if compressed and size / compressed >= PUMP_RATIO:
            out.append(f"{m['name']} declares {size:,} bytes from {compressed:,} compressed")
    return out
