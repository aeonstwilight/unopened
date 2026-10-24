# Triage report: `Invoice.pdf.lnk`

> Static analysis only. Nothing in this report came from running, opening or rendering the file.

|  |  |
|---|---|
| Verdict | **MALICIOUS** (high confidence, rule V-MAL-03) |
| File type | Windows shortcut (LNK) |
| Size | 618 bytes |
| SHA256 | `edb699ffa6c9feaba59d53e04f43e7af80e65c0d738bf0a44cb379bb300a9b76` |
| Checks incomplete | 1 (see warnings below) |
| Generated | 2026-10-24T22:23:48+00:00 by unopened 0.1.0 |

## Warning: some checks did not complete

- **yara**: UNAVAILABLE. no YARA rules configured; pass --yara-rules DIR or set UNOPENED\_YARA\_RULES

A check that did not complete is not a clean result.

## Verdict

**MALICIOUS**, high confidence.

- **V-MAL-03** (malicious): A shortcut launches a scripting or download tool (LOLBin) with an encoded, hidden, padded or URL-bearing command, or carries an appended program.
  - Shortcut launches powershell.exe
  - Encoded PowerShell command
  - Command asks for a hidden window
- **V-MAL-10** (malicious): Two or more HIGH findings from different analyzers.
  - File name does not match content
  - Shortcut launches powershell.exe
  - Encoded PowerShell command
- **V-SUS-01** (suspicious): At least one HIGH finding.
  - File name does not match content
  - Shortcut launches powershell.exe
  - Encoded PowerShell command
- note: some checks did not complete (yara unavailable); the evidence above still stands

_Produced by fixed, documented rules (verdict-rules in the project's docs folder), not by a model. Every verdict lists its reasons; see Not checked for what was not examined._

## Key findings

- **[HIGH] File name does not match content**: Double extension: the name looks like a .pdf file but the real extension is .lnk. Windows hides known extensions by default, so users see only the decoy.
- **[HIGH] Shortcut launches powershell.exe**: Runs PowerShell commands or scripts. Shortcuts delivered by email or download rarely have a good reason to start this program.
- **[HIGH] Encoded PowerShell command**: The command is base64-encoded so that it cannot be read at a glance. Decoded (shown as text, not run): Write-Host fixture
- **[MEDIUM] Shortcut borrows another program's icon**: It launches powershell.exe but shows the icon of msedge.exe, so it looks like a different kind of file.
- **[MEDIUM] Command asks for a hidden window**: The program is told to run without showing a window.
- **[LOW] Shortcut starts its program minimized**: Used to keep a console window from being noticed.

## File identity

|  |  |
|---|---|
| Name | `Invoice.pdf.lnk` |
| Identified as (from content) | Windows shortcut (LNK) |

**Name/content mismatches:**

- [HIGH] Double extension: the name looks like a .pdf file but the real extension is .lnk. Windows hides known extensions by default, so users see only the decoy.

## Hashes

| Hash | Value |
|---|---|
| MD5 | `af405e731e26d67f989e8ef75fa50359` |
| SHA1 | `d219c60a1034d83a547efdb38e53c900015d5c8f` |
| SHA256 | `edb699ffa6c9feaba59d53e04f43e7af80e65c0d738bf0a44cb379bb300a9b76` |
| TLSH | `T1D3F097312AF6079CF2B76730E7BAFA7885B3F819912443A9121248080E23794C860F73` |

## Shortcut (LNK)

| Field | Value |
|---|---|
| Target | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Arguments | `-NoProfile -WindowStyle Hidden -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgAGYAaQB4AHQAdQByAGUA` (95 chars) |
| Decoded command (text only) | `Write-Host fixture` |
| Icon | `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe` |
| Comment | `Invoice.pdf` |
| Window | `SW_SHOWMINNOACTIVE` |
| Creator machine (NetBIOS) | `fixture-pc` |
| Creator MAC address | `00:00:5e:00:53:01` |

## YARA

**Not checked** (UNAVAILABLE): no YARA rules configured; pass --yara-rules DIR or set UNOPENED\_YARA\_RULES

## Indicators

Extracted from strings in the file and from what the analyzers decoded (macro source, shortcut arguments). All network indicators are defanged. Presence of an indicator is a lead to pivot on, not proof of malicious behavior.

### Host names (1)

| Value | Seen | First offset | Found by | Notes |
|---|---|---|---|---|
| `fixture-pc` | 1 |  | lnk | lnk\_creator\_machine |

### MAC addresses (1)

| Value | Seen | First offset | Found by | Notes |
|---|---|---|---|---|
| `00:00:5e:00:53:01` | 1 |  | lnk | lnk\_creator\_machine |

### File paths (3)

| Value | Seen | First offset | Found by | Notes |
|---|---|---|---|---|
| `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe` | 1 |  | lnk |  |
| `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | 2 | 0x79 | strings, lnk |  |
| `` C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe` `` | 1 | 0xb6 | strings |  |

Strings examined: 2 ASCII and 1 UTF-16LE, minimum length 5.

## Hunt queries

Searches for this file's hashes, names and network indicators over the last 30 days. Hash and file-name queries can be pasted as they are. Network values below are defanged like the rest of this report; the paste-ready versions are in the `.hunt.txt` file written with `--out`, and in the JSON report under `hunt.raw`.

### Splunk (SPL)

**Hashes in any indexed data (raw terms)**

~~~
index=* earliest=-30d ("edb699ffa6c9feaba59d53e04f43e7af80e65c0d738bf0a44cb379bb300a9b76" OR "d219c60a1034d83a547efdb38e53c900015d5c8f" OR "af405e731e26d67f989e8ef75fa50359")
| stats count min(_time) as first max(_time) as last by index, sourcetype, host
~~~

**Hashes in the CIM Endpoint data model**

~~~
| tstats summariesonly=false count from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("edb699ffa6c9feaba59d53e04f43e7af80e65c0d738bf0a44cb379bb300a9b76", "d219c60a1034d83a547efdb38e53c900015d5c8f", "af405e731e26d67f989e8ef75fa50359") earliest=-30d
  by Filesystem.dest Filesystem.file_name Filesystem.file_path
~~~

**File names in the CIM Endpoint data model**

~~~
| tstats summariesonly=false count from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("Invoice.pdf.lnk") earliest=-30d
  by Filesystem.dest Filesystem.file_name Filesystem.file_path
~~~

### Microsoft Sentinel / Defender (KQL)

**Files, processes and email attachments with these hashes**

~~~
let sha256s = dynamic(["edb699ffa6c9feaba59d53e04f43e7af80e65c0d738bf0a44cb379bb300a9b76"]);
let sha1s = dynamic(["d219c60a1034d83a547efdb38e53c900015d5c8f"]);
let md5s = dynamic(["af405e731e26d67f989e8ef75fa50359"]);
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
let names = dynamic(["Invoice.pdf.lnk"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ (names)
| summarize count(), first = min(Timestamp), last = max(Timestamp)
    by DeviceName, FileName, FolderPath, SHA256
~~~

### Elastic (Kibana KQL, ECS fields)

**Files and processes with these hashes** (Set the time picker to the last 30 days.)

~~~
file.hash.sha256 : ("edb699ffa6c9feaba59d53e04f43e7af80e65c0d738bf0a44cb379bb300a9b76") or
process.hash.sha256 : ("edb699ffa6c9feaba59d53e04f43e7af80e65c0d738bf0a44cb379bb300a9b76") or
file.hash.sha1 : ("d219c60a1034d83a547efdb38e53c900015d5c8f") or
process.hash.sha1 : ("d219c60a1034d83a547efdb38e53c900015d5c8f") or
file.hash.md5 : ("af405e731e26d67f989e8ef75fa50359") or
process.hash.md5 : ("af405e731e26d67f989e8ef75fa50359")
~~~

**Files with these names** (Set the time picker to the last 30 days.)

~~~
file.name : ("Invoice.pdf.lnk")
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
| lnk | ran | 0.06s |  |
| email | not applicable | 0.00s |  |
| archive | not applicable | 0.00s |  |
| script | not applicable | 0.00s |  |
| pdf | not applicable | 0.00s |  |
| yara | UNAVAILABLE | 0.01s | no YARA rules configured; pass --yara-rules DIR or set UNOPENED\_YARA\_RULES |
| strings | ran | 0.00s |  |
| behavior | ran | 0.00s |  |

## Not checked

- **YARA rule scan**: unavailable: no YARA rules configured; pass --yara-rules DIR or set UNOPENED\_YARA\_RULES
- **Hash reputation lookup**: off; rerun with --reputation to look up the SHA256 at MalwareBazaar and VirusTotal (only the hash is sent)
