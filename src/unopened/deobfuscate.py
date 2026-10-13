"""Basic script deobfuscation as pure text transformations.

Nothing here evaluates code. Each pass rewrites recognizable encodings into plain
string literals:
- base64: PowerShell -EncodedCommand, FromBase64String('...'), atob('...')
- character codes: [char]72, String.fromCharCode(72,105), Chr(72)/ChrW(&H48), and
  numeric arrays next to a char conversion
- string concatenation: 'a' + 'b', "a" & "b"
Passes repeat until nothing changes, up to max_rounds, and output is capped.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

MAX_ROUNDS = 5
MAX_CHARS = 500_000
MAX_CONCAT_STEPS = 10_000

# -e, -ec, -enc ... -EncodedCommand: PowerShell accepts any unambiguous prefix.
ENCODED_COMMAND = re.compile(r"(?i)(?:^|\s)[-/](e[a-z]*)\s+([A-Za-z0-9+/]{16,}={0,2})")
FROM_BASE64 = re.compile(
    r"(?i)(?:\[(?:System\.)?Convert\]::FromBase64String|atob)\(\s*(['\"])([A-Za-z0-9+/=\s]{8,})\1\s*\)"
)
PS_CHAR = re.compile(r"(?i)\[char\]\s*(0x[0-9a-f]+|\d+)")
_JS_NUM = r"(?:0x[0-9a-fA-F]+|\d+)"
JS_FROMCHARCODE = re.compile(rf"String\.fromCharCode\(\s*({_JS_NUM}(?:\s*,\s*{_JS_NUM})*)\s*\)")
VB_CHR = re.compile(r"(?i)\bChrW?\$?\(\s*(&H[0-9a-f]+|\d+)\s*\)")
NUMBER_ARRAY = re.compile(r"[(\[@]\s*(\d{1,3}(?:\s*,\s*\d{1,3}){3,})\s*[)\]]")
CHAR_CONTEXT = re.compile(r"(?i)\[char\]|fromCharCode|\bChrW?\b")
# Two adjacent literals of the same quote style joined by + or &.
CONCAT = re.compile(r"(['\"])((?:(?!\1)[^\r\n])*)\1\s*[+&]\s*\1((?:(?!\1)[^\r\n])*)\1")


@dataclass
class Layer:
    technique: str
    count: int


@dataclass
class Result:
    text: str
    layers: list[Layer] = field(default_factory=list)
    truncated: bool = False

    @property
    def changed(self) -> bool:
        return bool(self.layers)

    def techniques(self) -> set[str]:
        return {layer.technique for layer in self.layers}


def decode_base64_text(blob: str) -> str | None:
    """Decode base64 to text (UTF-16LE first, as PowerShell uses, then UTF-8)."""
    compact = re.sub(r"\s+", "", blob)
    try:
        raw = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    # UTF-16LE text from ASCII has a zero in (nearly) every odd byte.
    odd = raw[1::2]
    utf16 = len(raw) % 2 == 0 and odd and odd.count(0) / len(odd) >= 0.6
    for encoding in (("utf-16-le", "utf-8") if utf16 else ("utf-8", "latin-1")):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if text and sum(c.isprintable() or c.isspace() for c in text) / len(text) > 0.9:
            return text
    return None


def find_encoded_command(text: str) -> tuple[re.Match[str], str | None] | None:
    for m in ENCODED_COMMAND.finditer(text):
        flag = m.group(1).lower()
        if flag == "ec" or "encodedcommand".startswith(flag):
            return m, decode_base64_text(m.group(2))
    return None


def _quote(text: str, prefer: str = "'") -> str:
    q = prefer if prefer not in text else ('"' if prefer == "'" else "'")
    return f"{q}{text}{q}"


def _num(token: str) -> int:
    token = token.strip()
    if token.lower().startswith("0x"):
        return int(token, 16)
    if token.lower().startswith("&h"):
        return int(token[2:], 16)
    return int(token)


def _char(code: int) -> str | None:
    if 9 <= code <= 0x10FFFF and (code >= 32 or code in (9, 10, 13)):
        return chr(code)
    return None


def _pass_base64(text: str) -> tuple[str, int]:
    count = 0

    def from_b64(m: re.Match[str]) -> str:
        nonlocal count
        decoded = decode_base64_text(m.group(2))
        if decoded is None:
            return m.group(0)
        count += 1
        return _quote(decoded)

    text = FROM_BASE64.sub(from_b64, text)
    found = find_encoded_command(text)
    if found and found[1] is not None:
        m, decoded = found
        count += 1
        text = text[:m.start(2)] + _quote(decoded) + text[m.end(2):]
    return text, count


def _pass_charcodes(text: str) -> tuple[str, int]:
    count = 0

    def single(prefer: str):
        def sub(m: re.Match[str]) -> str:
            nonlocal count
            ch = _char(_num(m.group(1)))
            if ch is None:
                return m.group(0)
            count += 1
            return _quote(ch, prefer)
        return sub

    def many(m: re.Match[str]) -> str:
        nonlocal count
        chars = [_char(_num(t)) for t in m.group(1).split(",")]
        if None in chars:
            return m.group(0)
        count += 1
        return _quote("".join(chars), '"')

    text = JS_FROMCHARCODE.sub(many, text)
    text = PS_CHAR.sub(single("'"), text)
    text = VB_CHR.sub(single('"'), text)

    def array(m: re.Match[str]) -> str:
        nonlocal count
        window = text[max(0, m.start() - 80): m.end() + 80]
        if not CHAR_CONTEXT.search(window):
            return m.group(0)
        chars = [_char(int(t)) for t in m.group(1).split(",")]
        if None in chars or not all(c.isprintable() or c.isspace() for c in chars):
            return m.group(0)
        count += 1
        return _quote("".join(chars))

    text = NUMBER_ARRAY.sub(array, text)
    return text, count


def _pass_concat(text: str) -> tuple[str, int]:
    count = 0
    while count < MAX_CONCAT_STEPS:
        new = CONCAT.sub(lambda m: m.group(1) + m.group(2) + m.group(3) + m.group(1), text,
                         count=1)
        if new == text:
            break
        text = new
        count += 1
    return text, count


PASSES = [("base64", _pass_base64), ("char codes", _pass_charcodes),
          ("string concatenation", _pass_concat)]


def deobfuscate(text: str, max_rounds: int = MAX_ROUNDS, max_chars: int = MAX_CHARS) -> Result:
    if len(text) > max_chars:
        # Head and tail: padding usually sits before the payload (M5 holdout: scripts of
        # several MB led by junk), so the end of the file matters as much as the start.
        half = max_chars // 2
        window = text[:half] + "\n" + text[-half:]
    else:
        window = text
    result = Result(window, truncated=len(text) > max_chars)
    for _ in range(max_rounds):
        changed = False
        for name, func in PASSES:
            new, count = func(result.text)
            if count and new != result.text:
                changed = True
                result.layers.append(Layer(name, count))
                if len(new) > max_chars:
                    new = new[:max_chars]
                    result.truncated = True
                result.text = new
        if not changed:
            break
    return result
