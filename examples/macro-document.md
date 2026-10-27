# Triage report: `Q3 report.doc`

> Static analysis only. Nothing in this report came from running, opening or rendering the file.

|  |  |
|---|---|
| Verdict | **MALICIOUS** (high confidence, rule V-MAL-02) |
| File type | Word 97-2003 document (OLE) with a VBA project (macros) |
| Size | 6,656 bytes |
| SHA256 | `614a9e295ec1ec86a7fed597801cefd16765be3ac129e23d34afe6a26673c2f0` |
| Checks incomplete | 1 (see warnings below) |
| Generated | 2026-10-27T20:09:29+00:00 by unopened 1.0.0 |

## Warning: some checks did not complete

- **yara**: UNAVAILABLE. no YARA rules configured; pass --yara-rules DIR or set UNOPENED\_YARA\_RULES

A check that did not complete is not a clean result.

## Verdict

**MALICIOUS**, high confidence.

- **V-MAL-02** (malicious): Office macros run automatically on open and use functions that run programs, download files or call Windows directly.
  - Macros run automatically (AutoOpen)
  - macro uses Shell, WScript[.]Shell
- **V-SUS-01** (suspicious): At least one HIGH finding.
  - Macros run automatically (AutoOpen)
- note: some checks did not complete (yara unavailable); the evidence above still stands

_Produced by fixed, documented rules (verdict-rules in the project's docs folder), not by a model. Every verdict lists its reasons; see Not checked for what was not examined._

## Key findings

- **[HIGH] Macros run automatically (AutoOpen)**: Code runs as soon as the document is opened or content is enabled, without the user clicking anything else.
- **[MEDIUM] Contains VBA macros (1 module(s))**: Macros are programs inside the document. Most legitimate documents have none.
- **[MEDIUM] Macro code uses suspicious functions**: CreateObject, Shell, WScript[.]Shell. These let a macro run programs, download files or hide its strings. Details are in the Office section.
- **[INFO] Network indicators found**: 1 url, 1 domain. See the Indicators section; these are pivots, not verdicts.

## File identity

|  |  |
|---|---|
| Name | `Q3 report.doc` |
| Identified as (from content) | Word 97-2003 document (OLE) with a VBA project (macros) |
| Subtype | word |

## Hashes

| Hash | Value |
|---|---|
| MD5 | `b79143deb24ddeac2e87e4ef4388e295` |
| SHA1 | `6a47c55eefeabe0fe51d38b7372fd30ee4fa5564` |
| SHA256 | `614a9e295ec1ec86a7fed597801cefd16765be3ac129e23d34afe6a26673c2f0` |
| TLSH | `T19ED1DC00B6A0C827D5A09EB24CE1F5086BB27C52EFD2035B31CCB3EF6A742D05A24565` |

## Office document

VBA macro modules: 1. XLM (Excel 4.0) macros: no.

**Auto-run triggers:**

- `AutoOpen`: Runs when the Word document is opened

**Suspicious keywords:**

- `Shell`: May run an executable file or a system command
- `WScript[.]Shell`: May run an executable file or a system command
- `CreateObject`: May create an OLE object

<details><summary>Macro source: Module1.bas (12 lines, from Macros/VBA/Module1)</summary>

~~~vb
Attribute VB_Name = "Module1"
Sub AutoOpen()
    ' Fixture macro: shows a message box and nothing else.
    MsgBox "unopened test fixture"
End Sub

Sub NeverCalled()
    ' Keyword bait for scanners, inside a string that is never used:
    Dim s As String
    s = "Shell CreateObject WScript[.]Shell hxxp://payload.example[.]com/x.exe"
End Sub

~~~

</details>

## YARA

**Not checked** (UNAVAILABLE): no YARA rules configured; pass --yara-rules DIR or set UNOPENED\_YARA\_RULES

## Indicators

Extracted from strings in the file and from what the analyzers decoded (macro source, shortcut arguments). All network indicators are defanged. Presence of an indicator is a lead to pivot on, not proof of malicious behavior.

### URLs (1)

| Value | Seen | First offset | Found by | Notes |
|---|---|---|---|---|
| `hxxp://payload.example[.]com/x.exe` | 2 |  | office |  |

### Domains (1)

| Value | Seen | First offset | Found by | Notes |
|---|---|---|---|---|
| `payload.example[.]com` | 2 |  | office |  |

Strings examined: 54 ASCII and 9 UTF-16LE, minimum length 5.

## Hunt queries

Searches for this file's hashes, names and network indicators over the last 30 days. Hash and file-name queries can be pasted as they are. Network values below are defanged like the rest of this report; the paste-ready versions are in the `.hunt.txt` file written with `--out`, and in the JSON report under `hunt.raw`.

### Splunk (SPL)

**Hashes in any indexed data (raw terms)**

~~~
index=* earliest=-30d ("614a9e295ec1ec86a7fed597801cefd16765be3ac129e23d34afe6a26673c2f0" OR "6a47c55eefeabe0fe51d38b7372fd30ee4fa5564" OR "b79143deb24ddeac2e87e4ef4388e295")
| stats count min(_time) as first max(_time) as last by index, sourcetype, host
~~~

**Hashes in the CIM Endpoint data model**

~~~
| tstats summariesonly=false count from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("614a9e295ec1ec86a7fed597801cefd16765be3ac129e23d34afe6a26673c2f0", "6a47c55eefeabe0fe51d38b7372fd30ee4fa5564", "b79143deb24ddeac2e87e4ef4388e295") earliest=-30d
  by Filesystem.dest Filesystem.file_name Filesystem.file_path
~~~

**File names in the CIM Endpoint data model**

~~~
| tstats summariesonly=false count from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("Q3 report.doc") earliest=-30d
  by Filesystem.dest Filesystem.file_name Filesystem.file_path
~~~

**DNS lookups of the domains (CIM Network\_Resolution)**

~~~
| tstats summariesonly=false count from datamodel=Network_Resolution where DNS.query IN ("payload.example[.]com") earliest=-30d
  by DNS.src DNS.query
~~~

**Requests for the URLs (CIM Web)**

~~~
| tstats summariesonly=false count from datamodel=Web where Web.url IN ("hxxp://payload.example[.]com/x.exe") earliest=-30d
  by Web.src Web.url
~~~

**Domains and IPs in any indexed data (raw terms)**

~~~
index=* earliest=-30d ("payload.example[.]com")
| stats count by index, sourcetype, host
~~~

### Microsoft Sentinel / Defender (KQL)

**Files, processes and email attachments with these hashes**

~~~
let sha256s = dynamic(["614a9e295ec1ec86a7fed597801cefd16765be3ac129e23d34afe6a26673c2f0"]);
let sha1s = dynamic(["6a47c55eefeabe0fe51d38b7372fd30ee4fa5564"]);
let md5s = dynamic(["b79143deb24ddeac2e87e4ef4388e295"]);
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
let names = dynamic(["Q3 report.doc"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ (names)
| summarize count(), first = min(Timestamp), last = max(Timestamp)
    by DeviceName, FileName, FolderPath, SHA256
~~~

**Network connections and DNS lookups**

~~~
let domains = dynamic(["payload.example[.]com"]);
let ips = dynamic([]);
let urls = dynamic(["hxxp://payload.example[.]com/x.exe"]);
union isfuzzy=true
  (DeviceNetworkEvents | where Timestamp > ago(30d)
     | where RemoteIP in (ips) or RemoteUrl has_any (domains) or RemoteUrl in (urls)
     | project TimeGenerated = Timestamp, Type, Computer = DeviceName, Remote = coalesce(RemoteUrl, RemoteIP)),
  (DnsEvents | where TimeGenerated > ago(30d) | where Name in~ (domains)
     | project TimeGenerated, Type, Computer, Remote = Name)
| summarize count(), first = min(TimeGenerated), last = max(TimeGenerated) by Type, Computer, Remote
~~~

### Elastic (Kibana KQL, ECS fields)

**Files and processes with these hashes** (Set the time picker to the last 30 days.)

~~~
file.hash.sha256 : ("614a9e295ec1ec86a7fed597801cefd16765be3ac129e23d34afe6a26673c2f0") or
process.hash.sha256 : ("614a9e295ec1ec86a7fed597801cefd16765be3ac129e23d34afe6a26673c2f0") or
file.hash.sha1 : ("6a47c55eefeabe0fe51d38b7372fd30ee4fa5564") or
process.hash.sha1 : ("6a47c55eefeabe0fe51d38b7372fd30ee4fa5564") or
file.hash.md5 : ("b79143deb24ddeac2e87e4ef4388e295") or
process.hash.md5 : ("b79143deb24ddeac2e87e4ef4388e295")
~~~

**Files with these names** (Set the time picker to the last 30 days.)

~~~
file.name : ("Q3 report.doc")
~~~

**Network connections, DNS and web requests** (Set the time picker to the last 30 days.)

~~~
dns.question.name : ("payload.example[.]com") or
url.domain : ("payload.example[.]com") or
url.full : ("hxxp://payload.example[.]com/x.exe")
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
| office | ran | 0.09s |  |
| lnk | not applicable | 0.00s |  |
| email | not applicable | 0.00s |  |
| archive | not applicable | 0.00s |  |
| script | not applicable | 0.00s |  |
| pdf | not applicable | 0.00s |  |
| web | not applicable | 0.00s |  |
| rtf | not applicable | 0.00s |  |
| vhd | not applicable | 0.00s |  |
| yara | UNAVAILABLE | 0.01s | no YARA rules configured; pass --yara-rules DIR or set UNOPENED\_YARA\_RULES |
| strings | ran | 0.00s |  |
| behavior | ran | 0.00s |  |

## Not checked

- **Office macros, auto-run triggers, embedded objects and external references**: DDE fields in legacy binary Word documents
- **YARA rule scan**: unavailable: no YARA rules configured; pass --yara-rules DIR or set UNOPENED\_YARA\_RULES
- **Files embedded in Office documents**: listed, not extracted or analyzed
- **Hash reputation lookup**: off; rerun with --reputation to look up the SHA256 at MalwareBazaar and VirusTotal (only the hash is sent)
