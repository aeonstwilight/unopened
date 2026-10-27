# Triage report: `Invoice.html`

> Static analysis only. Nothing in this report came from running, opening or rendering the file.

|  |  |
|---|---|
| Verdict | **MALICIOUS** (high confidence, rule V-MAL-06) |
| File type | HTML document |
| Size | 2,617 bytes |
| SHA256 | `880e8906903d4ca7d9c8b495bd589ece59afb47e262ccd42f7ab4234badb2249` |
| Checks incomplete | 1 (see warnings below) |
| Generated | 2026-10-27T20:09:30+00:00 by unopened 1.0.0 |

## Warning: some checks did not complete

- **yara**: UNAVAILABLE. no YARA rules configured; pass --yara-rules DIR or set UNOPENED\_YARA\_RULES

A check that did not complete is not a clean result.

## Verdict

**MALICIOUS**, high confidence.

- **V-MAL-06** (malicious): A document, RTF or PDF embeds, an email attaches, or a web page carries encoded, a file with an executable extension or content.
  - Embedded Windows program (PE): update.exe
- **V-MAL-11** (malicious): HTML smuggling: an HTML or SVG file decodes an embedded file, assembles it in the browser and hands it over as a download.
  - HTML smuggling: the page builds and drops a file
- **V-SUS-01** (suspicious): At least one HIGH finding.
  - HTML smuggling: the page builds and drops a file
  - Embedded Windows program (PE): update.exe
- note: some checks did not complete (yara unavailable); the evidence above still stands

_Produced by fixed, documented rules (verdict-rules in the project's docs folder), not by a model. Every verdict lists its reasons; see Not checked for what was not examined._

## Key findings

- **[HIGH] HTML smuggling: the page builds and drops a file**: The page decodes embedded data; assembles a file in the browser (Blob); hands it to the browser as a download; starts the download itself. Payload: update.exe (Windows program (PE), 1,536 bytes). Opening the page in a browser would save the file without it ever passing the mail gateway as an attachment.
- **[HIGH] Embedded Windows program (PE): update.exe**: Decoded from a base64 string (1,536 bytes, as a text transformation). It is analyzed below as a member.
- **[MEDIUM] Contains programs, shortcuts or scripts (1)**: update.exe. Delivering these inside an archive, image or email is a common way past mail filters.
- **[LOW] Very long line (2,065 characters)**: Long single lines usually hold encoded data or packed code.

## File identity

|  |  |
|---|---|
| Name | `Invoice.html` |
| Identified as (from content) | HTML document |
| Subtype | html |

## Hashes

| Hash | Value |
|---|---|
| MD5 | `bb753c06862fcddf7a4c71763560dd2a` |
| SHA1 | `233b64ac95ebd3b1ce217c850e8c033da6b0942c` |
| SHA256 | `880e8906903d4ca7d9c8b495bd589ece59afb47e262ccd42f7ab4234badb2249` |
| TLSH | `T1A551D07B1A16EC69AB3A3C84E4106E40BCE575377604C00AAFCCC83858B4915DEBA8B2` |

## Web page (HTML, SVG, HTA, WSF)

Type: html. 2,617 characters, 24 of them visible text. Script blocks: 1 (javascript), event handlers: 0, links: 0, password fields: 0. Tokenized as text; nothing was rendered, run or fetched.

Title: `Document viewer`

**Smuggling steps:** decodes embedded data; assembles a file in the browser (Blob); hands it to the browser as a download; starts the download itself.

**Embedded payloads** (decoded as text, analyzed below as members):

| Name | Type | Size | Found in |
|---|---|---|---|
| `update.exe` | Windows program (PE) | 1,536 | base64 string |

## YARA

**Not checked** (UNAVAILABLE): no YARA rules configured; pass --yara-rules DIR or set UNOPENED\_YARA\_RULES

## Members

Each extracted member was triaged on its own. Their indicators are merged into the Indicators section below.

### Member: `update.exe`

|  |  |
|---|---|
| Verdict | **NO FINDINGS** (low, V-NF-01) |
| Type | PE32 executable (x86, console) |
| Size | 1,536 bytes |
| SHA256 | `c6e3459a8967784cba2e9d8a0001f7a101b5b3d5e0bd82a27da3147f1128da13` |

Not fully checked: capa UNAVAILABLE; yara UNAVAILABLE

## Indicators

Extracted from strings in the file and from what the analyzers decoded (macro source, shortcut arguments). All network indicators are defanged. Presence of an indicator is a lead to pivot on, not proof of malicious behavior.

### File paths (1)

| Value | Seen | First offset | Found by | Notes |
|---|---|---|---|---|
| `C:\build\fixture\Release\fixture.pdb` | 1 | 0x4f8 | member update.exe: strings |  |

Strings examined: 14 ASCII and 0 UTF-16LE, minimum length 5.

## Hunt queries

Searches for this file's hashes, names and network indicators over the last 30 days. Hash and file-name queries can be pasted as they are. Network values below are defanged like the rest of this report; the paste-ready versions are in the `.hunt.txt` file written with `--out`, and in the JSON report under `hunt.raw`.

### Splunk (SPL)

**Hashes in any indexed data (raw terms)**

~~~
index=* earliest=-30d ("880e8906903d4ca7d9c8b495bd589ece59afb47e262ccd42f7ab4234badb2249" OR "c6e3459a8967784cba2e9d8a0001f7a101b5b3d5e0bd82a27da3147f1128da13" OR "233b64ac95ebd3b1ce217c850e8c033da6b0942c" OR "0ecdfbcfbde5d63e55288515ba4d449996ba84cd" OR "bb753c06862fcddf7a4c71763560dd2a" OR "365e02f18584347f8ecf5f924b57c10b")
| stats count min(_time) as first max(_time) as last by index, sourcetype, host
~~~

**Hashes in the CIM Endpoint data model**

~~~
| tstats summariesonly=false count from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("880e8906903d4ca7d9c8b495bd589ece59afb47e262ccd42f7ab4234badb2249", "c6e3459a8967784cba2e9d8a0001f7a101b5b3d5e0bd82a27da3147f1128da13", "233b64ac95ebd3b1ce217c850e8c033da6b0942c", "0ecdfbcfbde5d63e55288515ba4d449996ba84cd", "bb753c06862fcddf7a4c71763560dd2a", "365e02f18584347f8ecf5f924b57c10b") earliest=-30d
  by Filesystem.dest Filesystem.file_name Filesystem.file_path
~~~

**File names in the CIM Endpoint data model**

~~~
| tstats summariesonly=false count from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("Invoice.html", "update.exe") earliest=-30d
  by Filesystem.dest Filesystem.file_name Filesystem.file_path
~~~

### Microsoft Sentinel / Defender (KQL)

**Files, processes and email attachments with these hashes**

~~~
let sha256s = dynamic(["880e8906903d4ca7d9c8b495bd589ece59afb47e262ccd42f7ab4234badb2249", "c6e3459a8967784cba2e9d8a0001f7a101b5b3d5e0bd82a27da3147f1128da13"]);
let sha1s = dynamic(["233b64ac95ebd3b1ce217c850e8c033da6b0942c", "0ecdfbcfbde5d63e55288515ba4d449996ba84cd"]);
let md5s = dynamic(["bb753c06862fcddf7a4c71763560dd2a", "365e02f18584347f8ecf5f924b57c10b"]);
union isfuzzy=true
  (DeviceFileEvents | where SHA256 in (sha256s) or SHA1 in (sha1s) or MD5 in (md5s)),
  (DeviceProcessEvents | where SHA256 in (sha256s) or SHA1 in (sha1s) or MD5 in (md5s)),
  (EmailAttachmentInfo | where SHA256 in (sha256s))
| where Timestamp > ago(30d)
| summarize count(), first = min(Timestamp), last = max(Timestamp)
    by Type, DeviceName, FileName, SHA256
~~~

**Files with these names**

~~~
let names = dynamic(["Invoice.html", "update.exe"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ (names)
| summarize count(), first = min(Timestamp), last = max(Timestamp)
    by DeviceName, FileName, FolderPath, SHA256
~~~

### Elastic (Kibana KQL, ECS fields)

**Files and processes with these hashes** (Set the time picker to the last 30 days.)

~~~
file.hash.sha256 : ("880e8906903d4ca7d9c8b495bd589ece59afb47e262ccd42f7ab4234badb2249" or "c6e3459a8967784cba2e9d8a0001f7a101b5b3d5e0bd82a27da3147f1128da13") or
process.hash.sha256 : ("880e8906903d4ca7d9c8b495bd589ece59afb47e262ccd42f7ab4234badb2249" or "c6e3459a8967784cba2e9d8a0001f7a101b5b3d5e0bd82a27da3147f1128da13") or
file.hash.sha1 : ("233b64ac95ebd3b1ce217c850e8c033da6b0942c" or "0ecdfbcfbde5d63e55288515ba4d449996ba84cd") or
process.hash.sha1 : ("233b64ac95ebd3b1ce217c850e8c033da6b0942c" or "0ecdfbcfbde5d63e55288515ba4d449996ba84cd") or
file.hash.md5 : ("bb753c06862fcddf7a4c71763560dd2a" or "365e02f18584347f8ecf5f924b57c10b") or
process.hash.md5 : ("bb753c06862fcddf7a4c71763560dd2a" or "365e02f18584347f8ecf5f924b57c10b")
~~~

**Files with these names** (Set the time picker to the last 30 days.)

~~~
file.name : ("Invoice.html" or "update.exe")
~~~

## Analyzer status

| Analyzer | Status | Time | Message |
|---|---|---|---|
| hashes | ran | 0.00s |  |
| tlsh | ran | 0.01s |  |
| pe | not applicable | 0.00s |  |
| authenticode | not applicable | 0.00s |  |
| capa | not applicable | 0.00s |  |
| floss | not applicable | 0.00s |  |
| office | not applicable | 0.00s |  |
| lnk | not applicable | 0.00s |  |
| email | not applicable | 0.00s |  |
| archive | not applicable | 0.00s |  |
| script | not applicable | 0.00s |  |
| pdf | not applicable | 0.00s |  |
| web | ran | 0.01s |  |
| rtf | not applicable | 0.00s |  |
| vhd | not applicable | 0.00s |  |
| yara | UNAVAILABLE | 0.01s | no YARA rules configured; pass --yara-rules DIR or set UNOPENED\_YARA\_RULES |
| strings | ran | 0.00s |  |
| behavior | ran | 0.00s |  |

## Not checked

- **YARA rule scan**: unavailable: no YARA rules configured; pass --yara-rules DIR or set UNOPENED\_YARA\_RULES
- **Hash reputation lookup**: off; rerun with --reputation to look up the SHA256 at MalwareBazaar and VirusTotal (only the hash is sent)
