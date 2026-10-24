# Triage report: `Action required.eml`

> Static analysis only. Nothing in this report came from running, opening or rendering the file.

|  |  |
|---|---|
| Verdict | **MALICIOUS** (high confidence, rule V-MAL-06) |
| File type | Email message (.eml, RFC 5322) |
| Size | 2,939 bytes |
| SHA256 | `3e8247aac41f0b71f906ef15994a7fbf41a25f8fc7e9ba012747ee330c235904` |
| Checks incomplete | 1 (see warnings below) |
| Generated | 2026-10-24T22:23:48+00:00 by unopened 0.1.0 |

## Warning: some checks did not complete

- **yara**: UNAVAILABLE. no YARA rules configured; pass --yara-rules DIR or set UNOPENED\_YARA\_RULES

A check that did not complete is not a clean result.

## Verdict

**MALICIOUS**, high confidence.

- **V-MAL-06** (malicious): A document or PDF embeds, or an email attaches, a file with an executable extension.
  - Attachment with a runnable extension: Invoice.pdf.lnk
- **V-MAL-09** (malicious): A member of this archive, disk image, PDF or email was judged malicious.
  - Invoice.pdf.lnk: malicious (high)
- **V-MAL-10** (malicious): Two or more HIGH findings from different analyzers.
  - DMARC failed for the sender's domain
  - The sender domain imitates microsoft
  - The email body contains a form with a password field
  - Links go to domains imitating a known brand
  - Attachment with a runnable extension: Invoice.pdf.lnk
  - Member disguised as a different file type
- **V-SUS-01** (suspicious): At least one HIGH finding.
  - DMARC failed for the sender's domain
  - The sender domain imitates microsoft
  - The email body contains a form with a password field
  - Links go to domains imitating a known brand
  - Attachment with a runnable extension: Invoice.pdf.lnk
  - Member disguised as a different file type
- **V-SUS-04** (suspicious): Three or more MEDIUM findings.
  - Sender authentication failed: spf=fail
  - Display name uses the microsoft brand, but the address is not theirs
  - Replies go to a different organization than the sender
  - Link text names a different site than the link opens (1)
  - Links point to raw IP addresses
  - HTML attachment: Statement.html
  - Contains programs, shortcuts or scripts (1)
- note: some checks did not complete (yara unavailable); the evidence above still stands

_Produced by fixed, documented rules (verdict-rules in the project's docs folder), not by a model. Every verdict lists its reasons; see Not checked for what was not examined._

## Key findings

- **[HIGH] DMARC failed for the sender's domain**: The receiving server recorded dmarc=fail: the message is not authenticated as coming from micros0ft-support.example[.]com. The From address is likely spoofed.
- **[HIGH] The sender domain imitates microsoft**: 'micros0ft-support.example[.]com' contains the microsoft name but is not one of its domains.
- **[HIGH] The email body contains a form with a password field**: Submits to 'hxxps://collect.example[.]net/post'. Legitimate mail almost never asks for input in the message itself; this is a credential-harvesting pattern.
- **[HIGH] Links go to domains imitating a known brand**: login.micros0ft-support.example[.]com (microsoft)
- **[HIGH] Attachment with a runnable extension: Invoice.pdf.lnk**: Windows runs .lnk files on double-click. Analyzed below.
- **[HIGH] Member disguised as a different file type**: Invoice.pdf.lnk. See the member's section for details.
- **[MEDIUM] Sender authentication failed: spf=fail**: Recorded by the receiving server. Forwarding and mailing lists can break SPF and DKIM, so read this with the other findings.
- **[MEDIUM] Display name uses the microsoft brand, but the address is not theirs**: 'Microsoft 365' sent from 'micros0ft-support.example[.]com'.
- **[MEDIUM] Replies go to a different organization than the sender**: From 'micros0ft-support.example[.]com', Reply-To 'example[.]org'. A common setup for invoice and payroll fraud: the reply reaches the attacker.
- **[MEDIUM] Link text names a different site than the link opens (1)**: login.microsoftonline[.]com -\> login.micros0ft-support.example[.]com. Mailing services also do this for click tracking, so check the destinations.
- **[MEDIUM] Links point to raw IP addresses**: 192.0.2[.]10
- **[MEDIUM] HTML attachment: Statement.html**: Opens in a browser from the local disk, out of reach of URL filtering: used for fake sign-in pages and HTML smuggling.
- **[MEDIUM] Contains programs, shortcuts or scripts (1)**: Invoice.pdf.lnk. Delivering these inside an archive, image or email is a common way past mail filters.
- **[LOW] Bounce address is at a different domain than the From address**: Return-Path 'example[.]net'. Normal for mailing services and newsletters; notable together with other findings.
- **[INFO] Links (3)**: Listed below and as indicators (defanged). None were followed.
- **[INFO] Attachments (2)**: Each one is extracted and analyzed below.
- **[INFO] Network indicators found**: 6 url, 10 domain, 2 ipv4, 5 email. See the Indicators section; these are pivots, not verdicts.

## File identity

|  |  |
|---|---|
| Name | `Action required.eml` |
| Identified as (from content) | Email message (.eml, RFC 5322) |
| Subtype | eml |

## Hashes

| Hash | Value |
|---|---|
| MD5 | `7297bc3f10a71a0c4a6645a30643f6ba` |
| SHA1 | `a1d0c98b688e65e4b1abe6af08f3270fe17eccc0` |
| SHA256 | `3e8247aac41f0b71f906ef15994a7fbf41a25f8fc7e9ba012747ee330c235904` |
| TLSH | `T12F51B4B28E013989932EBD48515035282D3056A719C7F9A4EED846F91CCCB8EF7F26C8` |

## Email

Format: EML.

| Header | Value |
|---|---|
| From | `Microsoft 365 <no-reply[@]micros0ft-support.example[.]com>` |
| Reply-To | `helpdesk[@]example[.]org` |
| Return-Path | `<bounce[@]example[.]net>` |
| To | `user[@]example[.]com` |
| Subject | `Action required: mailbox quota` |
| Date | `Mon, 19 Oct 2026 09:00:00 +0000` |
| Message-ID | `<phish-1[@]example[.]net>` |
| Authentication | SPF `fail`, DKIM `none`, DMARC `fail` (from Authentication-Results, topmost header) |
| Received hops | 1 |

Links (3), none followed:

| Link text | Opens | Notes |
|---|---|---|
| `hxxps://login.microsoftonline[.]com` | `hxxps://login.micros0ft-support.example[.]com/owa/?u=1` | text shows login.microsoftonline[.]com |
| `Verify now` | `hxxp://192.0.2[.]10/verify` |  |
| `(plain text)` | `hxxps://login.micros0ft-support.example[.]com/owa` |  |

- Form submitting to `hxxps://collect.example[.]net/post` with a password field

| Attachment | Declared type | Size | Notes |
|---|---|---|---|
| `Invoice.pdf.lnk` | application/octet-stream | 618 |  |
| `Statement.html` | text/html | 41 |  |

## YARA

**Not checked** (UNAVAILABLE): no YARA rules configured; pass --yara-rules DIR or set UNOPENED\_YARA\_RULES

## Members

Each extracted member was triaged on its own. Their indicators are merged into the Indicators section below.

### Member: `Invoice.pdf.lnk`

|  |  |
|---|---|
| Verdict | **MALICIOUS** (high, V-MAL-03) |
| Type | Windows shortcut (LNK) |
| Size | 618 bytes |
| SHA256 | `edb699ffa6c9feaba59d53e04f43e7af80e65c0d738bf0a44cb379bb300a9b76` |

- **[HIGH] File name does not match content**: Double extension: the name looks like a .pdf file but the real extension is .lnk. Windows hides known extensions by default, so users see only the decoy.
- **[HIGH] Shortcut launches powershell.exe**: Runs PowerShell commands or scripts. Shortcuts delivered by email or download rarely have a good reason to start this program.
- **[HIGH] Encoded PowerShell command**: The command is base64-encoded so that it cannot be read at a glance. Decoded (shown as text, not run): Write-Host fixture
- **[MEDIUM] Shortcut borrows another program's icon**: It launches powershell.exe but shows the icon of msedge.exe, so it looks like a different kind of file.
- **[MEDIUM] Command asks for a hidden window**: The program is told to run without showing a window.
- **[LOW] Shortcut starts its program minimized**: Used to keep a console window from being noticed.

Not fully checked: yara UNAVAILABLE

### Member: `Statement.html`

|  |  |
|---|---|
| Verdict | **NO FINDINGS** (low, V-NF-01) |
| Type | Plain text (no supported script language recognized) |
| Size | 41 bytes |
| SHA256 | `504b6ce5d5fef8e932d9ee4cb07554f42b5200de47dee1bbdea84d65ea1dce84` |

Not fully checked: yara UNAVAILABLE

## Indicators

Extracted from strings in the file and from what the analyzers decoded (macro source, shortcut arguments). All network indicators are defanged. Presence of an indicator is a lead to pivot on, not proof of malicious behavior.

### URLs (6)

| Value | Seen | First offset | Found by | Notes |
|---|---|---|---|---|
| `hxxps://login.micros0ft-support.example[.]com/owa/?u=1` | 1 |  | email |  |
| `hxxps://login.micros0ft-support.example[.]com/owa` | 3 | 0x3aa | strings, email |  |
| `hxxps://login.micros0ft-support.example[.]com/owa/?u=3D1` | 1 | 0x4df | strings |  |
| `hxxps://login.microsoftonline[.]com` | 2 | 0x4df | strings, email |  |
| `hxxp://192.0.2[.]10/verify` | 2 | 0x54f | strings, email |  |
| `hxxps://collect.example[.]net/post` | 1 | 0x58a | strings |  |

### Domains (10)

| Value | Seen | First offset | Found by | Notes |
|---|---|---|---|---|
| `mail.example[.]net` | 2 | 0x0 | strings, email |  |
| `mx.example[.]com` | 3 | 0x43 | strings, email |  |
| `example[.]net` | 4 | 0x74 | strings, email |  |
| `micros0ft-support.example[.]com` | 3 | 0xc0 | strings, email |  |
| `forged.example[.]net` | 1 | 0x101 | strings |  |
| `example[.]org` | 2 | 0x18a | strings, email |  |
| `example[.]com` | 1 | 0x1cb | strings |  |
| `login.micros0ft-support.example[.]com` | 5 | 0x3aa | strings, email |  |
| `login.microsoftonline[.]com` | 2 | 0x4df | strings, email |  |
| `collect.example[.]net` | 1 | 0x58a | strings |  |

### IPv4 addresses (2)

| Value | Seen | First offset | Found by | Notes |
|---|---|---|---|---|
| `192.0.2[.]25` | 2 | 0x0 | strings, email | private\_or\_reserved |
| `192.0.2[.]10` | 2 | 0x54f | strings, email | private\_or\_reserved |

### Email addresses (5)

| Value | Seen | First offset | Found by | Notes |
|---|---|---|---|---|
| `no-reply[@]micros0ft-support.example[.]com` | 2 | 0x14d | strings, email |  |
| `helpdesk[@]example[.]org` | 2 | 0x18a | strings, email |  |
| `bounce[@]example[.]net` | 2 | 0x1a9 | strings, email |  |
| `user[@]example[.]com` | 1 | 0x1cb | strings |  |
| `phish-1[@]example[.]net` | 1 | 0x22e | strings |  |

### Host names (1)

| Value | Seen | First offset | Found by | Notes |
|---|---|---|---|---|
| `fixture-pc` | 1 |  | member Invoice.pdf.lnk: lnk | lnk\_creator\_machine |

### MAC addresses (1)

| Value | Seen | First offset | Found by | Notes |
|---|---|---|---|---|
| `00:00:5e:00:53:01` | 1 |  | member Invoice.pdf.lnk: lnk | lnk\_creator\_machine |

### File paths (3)

| Value | Seen | First offset | Found by | Notes |
|---|---|---|---|---|
| `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe` | 1 |  | member Invoice.pdf.lnk: lnk |  |
| `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | 2 | 0x79 | member Invoice.pdf.lnk: strings, member Invoice.pdf.lnk: lnk |  |
| `` C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe` `` | 1 | 0xb6 | member Invoice.pdf.lnk: strings |  |

Strings examined: 52 ASCII and 0 UTF-16LE, minimum length 5.

## Hunt queries

Searches for this file's hashes, names and network indicators over the last 30 days. Hash and file-name queries can be pasted as they are. Network values below are defanged like the rest of this report; the paste-ready versions are in the `.hunt.txt` file written with `--out`, and in the JSON report under `hunt.raw`.

### Splunk (SPL)

**Hashes in any indexed data (raw terms)**

~~~
index=* earliest=-30d ("3e8247aac41f0b71f906ef15994a7fbf41a25f8fc7e9ba012747ee330c235904" OR "edb699ffa6c9feaba59d53e04f43e7af80e65c0d738bf0a44cb379bb300a9b76" OR "504b6ce5d5fef8e932d9ee4cb07554f42b5200de47dee1bbdea84d65ea1dce84" OR "a1d0c98b688e65e4b1abe6af08f3270fe17eccc0" OR "d219c60a1034d83a547efdb38e53c900015d5c8f" OR "643ce69f2f058f7893be0d54a494fc8876b340da" OR "7297bc3f10a71a0c4a6645a30643f6ba" OR "af405e731e26d67f989e8ef75fa50359" OR "8070039581456a1430f4500def301b68")
| stats count min(_time) as first max(_time) as last by index, sourcetype, host
~~~

**Hashes in the CIM Endpoint data model**

~~~
| tstats summariesonly=false count from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("3e8247aac41f0b71f906ef15994a7fbf41a25f8fc7e9ba012747ee330c235904", "edb699ffa6c9feaba59d53e04f43e7af80e65c0d738bf0a44cb379bb300a9b76", "504b6ce5d5fef8e932d9ee4cb07554f42b5200de47dee1bbdea84d65ea1dce84", "a1d0c98b688e65e4b1abe6af08f3270fe17eccc0", "d219c60a1034d83a547efdb38e53c900015d5c8f", "643ce69f2f058f7893be0d54a494fc8876b340da", "7297bc3f10a71a0c4a6645a30643f6ba", "af405e731e26d67f989e8ef75fa50359", "8070039581456a1430f4500def301b68") earliest=-30d
  by Filesystem.dest Filesystem.file_name Filesystem.file_path
~~~

**File names in the CIM Endpoint data model**

~~~
| tstats summariesonly=false count from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("Action required.eml", "Invoice.pdf.lnk", "Statement.html") earliest=-30d
  by Filesystem.dest Filesystem.file_name Filesystem.file_path
~~~

**DNS lookups of the domains (CIM Network\_Resolution)**

~~~
| tstats summariesonly=false count from datamodel=Network_Resolution where DNS.query IN ("mail.example[.]net", "mx.example[.]com", "example[.]net", "micros0ft-support.example[.]com", "forged.example[.]net", "example[.]org", "example[.]com", "login.micros0ft-support.example[.]com", "login.microsoftonline[.]com", "collect.example[.]net") earliest=-30d
  by DNS.src DNS.query
~~~

**Requests for the URLs (CIM Web)**

~~~
| tstats summariesonly=false count from datamodel=Web where Web.url IN ("hxxps://login.micros0ft-support.example[.]com/owa/?u=1", "hxxps://login.micros0ft-support.example[.]com/owa", "hxxps://login.micros0ft-support.example[.]com/owa/?u=3D1", "hxxps://login.microsoftonline[.]com", "hxxp://192.0.2[.]10/verify", "hxxps://collect.example[.]net/post") earliest=-30d
  by Web.src Web.url
~~~

**Other deliveries of this email (CIM Email)**

~~~
| tstats summariesonly=false count from datamodel=Email where (All_Email.src_user IN ("no-reply[@]micros0ft-support.example[.]com") OR All_Email.subject IN ("Action required: mailbox quota")) earliest=-30d
  by All_Email.recipient All_Email.src_user All_Email.subject
~~~

**Domains and IPs in any indexed data (raw terms)**

~~~
index=* earliest=-30d ("mail.example[.]net" OR "mx.example[.]com" OR "example[.]net" OR "micros0ft-support.example[.]com" OR "forged.example[.]net" OR "example[.]org" OR "example[.]com" OR "login.micros0ft-support.example[.]com" OR "login.microsoftonline[.]com" OR "collect.example[.]net")
| stats count by index, sourcetype, host
~~~

### Microsoft Sentinel / Defender (KQL)

**Files, processes and email attachments with these hashes**

~~~
let sha256s = dynamic(["3e8247aac41f0b71f906ef15994a7fbf41a25f8fc7e9ba012747ee330c235904", "edb699ffa6c9feaba59d53e04f43e7af80e65c0d738bf0a44cb379bb300a9b76", "504b6ce5d5fef8e932d9ee4cb07554f42b5200de47dee1bbdea84d65ea1dce84"]);
let sha1s = dynamic(["a1d0c98b688e65e4b1abe6af08f3270fe17eccc0", "d219c60a1034d83a547efdb38e53c900015d5c8f", "643ce69f2f058f7893be0d54a494fc8876b340da"]);
let md5s = dynamic(["7297bc3f10a71a0c4a6645a30643f6ba", "af405e731e26d67f989e8ef75fa50359", "8070039581456a1430f4500def301b68"]);
union isfuzzy=true
  (DeviceFileEvents | where SHA256 in (sha256s) or SHA1 in (sha1s) or MD5 in (md5s)),
  (DeviceProcessEvents | where SHA256 in (sha256s) or SHA1 in (sha1s) or MD5 in (md5s)),
  (EmailAttachmentInfo | where SHA256 in (sha256s))
| where Timestamp > ago(30d)
| summarize count(), first = min(Timestamp), last = max(Timestamp)
    by Type, DeviceName, FileName, SHA256
~~~

**Other deliveries of this email (Defender for Office 365)**

~~~
let senders = dynamic(["no-reply[@]micros0ft-support.example[.]com"]);
let subjects = dynamic(["Action required: mailbox quota"]);
let ids = dynamic(["<phish-1[@]example[.]net>"]);
EmailEvents
| where Timestamp > ago(30d)
| where SenderFromAddress in~ (senders) or Subject in (subjects) or InternetMessageId in (ids)
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject,
    DeliveryAction, DeliveryLocation, NetworkMessageId
~~~

**Who else received these links (Defender for Office 365)**

~~~
let urls = dynamic(["hxxps://login.micros0ft-support.example[.]com/owa/?u=1", "hxxps://login.micros0ft-support.example[.]com/owa", "hxxps://login.micros0ft-support.example[.]com/owa/?u=3D1", "hxxps://login.microsoftonline[.]com", "hxxp://192.0.2[.]10/verify", "hxxps://collect.example[.]net/post"]);
let domains = dynamic(["mail.example[.]net", "mx.example[.]com", "example[.]net", "micros0ft-support.example[.]com", "forged.example[.]net", "example[.]org", "example[.]com", "login.micros0ft-support.example[.]com", "login.microsoftonline[.]com", "collect.example[.]net"]);
EmailUrlInfo
| where Timestamp > ago(30d)
| where Url in (urls) or UrlDomain in~ (domains)
| join kind=inner (EmailEvents | project NetworkMessageId, RecipientEmailAddress, Subject) on NetworkMessageId
| summarize count() by Url, RecipientEmailAddress, Subject
~~~

**Files with these names**

~~~
let names = dynamic(["Action required.eml", "Invoice.pdf.lnk", "Statement.html"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ (names)
| summarize count(), first = min(Timestamp), last = max(Timestamp)
    by DeviceName, FileName, FolderPath, SHA256
~~~

**Network connections and DNS lookups**

~~~
let domains = dynamic(["mail.example[.]net", "mx.example[.]com", "example[.]net", "micros0ft-support.example[.]com", "forged.example[.]net", "example[.]org", "example[.]com", "login.micros0ft-support.example[.]com", "login.microsoftonline[.]com", "collect.example[.]net"]);
let ips = dynamic([]);
let urls = dynamic(["hxxps://login.micros0ft-support.example[.]com/owa/?u=1", "hxxps://login.micros0ft-support.example[.]com/owa", "hxxps://login.micros0ft-support.example[.]com/owa/?u=3D1", "hxxps://login.microsoftonline[.]com", "hxxp://192.0.2[.]10/verify", "hxxps://collect.example[.]net/post"]);
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
file.hash.sha256 : ("3e8247aac41f0b71f906ef15994a7fbf41a25f8fc7e9ba012747ee330c235904" or "edb699ffa6c9feaba59d53e04f43e7af80e65c0d738bf0a44cb379bb300a9b76" or "504b6ce5d5fef8e932d9ee4cb07554f42b5200de47dee1bbdea84d65ea1dce84") or
process.hash.sha256 : ("3e8247aac41f0b71f906ef15994a7fbf41a25f8fc7e9ba012747ee330c235904" or "edb699ffa6c9feaba59d53e04f43e7af80e65c0d738bf0a44cb379bb300a9b76" or "504b6ce5d5fef8e932d9ee4cb07554f42b5200de47dee1bbdea84d65ea1dce84") or
file.hash.sha1 : ("a1d0c98b688e65e4b1abe6af08f3270fe17eccc0" or "d219c60a1034d83a547efdb38e53c900015d5c8f" or "643ce69f2f058f7893be0d54a494fc8876b340da") or
process.hash.sha1 : ("a1d0c98b688e65e4b1abe6af08f3270fe17eccc0" or "d219c60a1034d83a547efdb38e53c900015d5c8f" or "643ce69f2f058f7893be0d54a494fc8876b340da") or
file.hash.md5 : ("7297bc3f10a71a0c4a6645a30643f6ba" or "af405e731e26d67f989e8ef75fa50359" or "8070039581456a1430f4500def301b68") or
process.hash.md5 : ("7297bc3f10a71a0c4a6645a30643f6ba" or "af405e731e26d67f989e8ef75fa50359" or "8070039581456a1430f4500def301b68")
~~~

**Files with these names** (Set the time picker to the last 30 days.)

~~~
file.name : ("Action required.eml" or "Invoice.pdf.lnk" or "Statement.html")
~~~

**Other deliveries of this email (ECS email fields)** (Set the time picker to the last 30 days.)

~~~
email.from.address : ("no-reply[@]micros0ft-support.example[.]com") or
email.subject : ("Action required: mailbox quota") or
email.message_id : ("phish-1[@]example[.]net")
~~~

**Network connections, DNS and web requests** (Set the time picker to the last 30 days.)

~~~
dns.question.name : ("mail.example[.]net" or "mx.example[.]com" or "example[.]net" or "micros0ft-support.example[.]com" or "forged.example[.]net" or "example[.]org" or "example[.]com" or "login.micros0ft-support.example[.]com" or "login.microsoftonline[.]com" or "collect.example[.]net") or
url.domain : ("mail.example[.]net" or "mx.example[.]com" or "example[.]net" or "micros0ft-support.example[.]com" or "forged.example[.]net" or "example[.]org" or "example[.]com" or "login.micros0ft-support.example[.]com" or "login.microsoftonline[.]com" or "collect.example[.]net") or
url.full : ("hxxps://login.micros0ft-support.example[.]com/owa/?u=1" or "hxxps://login.micros0ft-support.example[.]com/owa" or "hxxps://login.micros0ft-support.example[.]com/owa/?u=3D1" or "hxxps://login.microsoftonline[.]com" or "hxxp://192.0.2[.]10/verify" or "hxxps://collect.example[.]net/post")
~~~

## Analyzer status

| Analyzer | Status | Time | Message |
|---|---|---|---|
| hashes | ran | 0.01s |  |
| tlsh | ran | 0.01s |  |
| pe | not applicable | 0.00s |  |
| authenticode | not applicable | 0.00s |  |
| capa | not applicable | 0.00s |  |
| floss | not applicable | 0.00s |  |
| office | not applicable | 0.00s |  |
| lnk | not applicable | 0.00s |  |
| email | ran | 0.02s |  |
| archive | not applicable | 0.00s |  |
| script | not applicable | 0.00s |  |
| pdf | not applicable | 0.00s |  |
| yara | UNAVAILABLE | 0.01s | no YARA rules configured; pass --yara-rules DIR or set UNOPENED\_YARA\_RULES |
| strings | ran | 0.01s |  |
| behavior | ran | 0.00s |  |

## Not checked

- **YARA rule scan**: unavailable: no YARA rules configured; pass --yara-rules DIR or set UNOPENED\_YARA\_RULES
- **Hash reputation lookup**: off; rerun with --reputation to look up the SHA256 at MalwareBazaar and VirusTotal (only the hash is sent)
