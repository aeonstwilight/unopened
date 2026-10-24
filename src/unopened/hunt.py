"""Indicator search snippets for Splunk (SPL), Microsoft Sentinel / Defender (KQL) and
Elastic (Kibana KQL over ECS), so an analyst can pivot immediately.

Queries are built from raw indicator values, because a query needs the real value.
In the Markdown report they pass through the same final defang step as everything else
(hash and file-name queries are unaffected; network queries come out defanged). The
paste-ready raw queries are written to <sha256>.hunt.txt and to JSON under hunt.raw.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
from dataclasses import field as dc_field
from typing import Any

MAX_VALUES = 50
EXCLUDED_IP_TAGS = {"private_or_reserved", "loopback", "link_local", "multicast",
                    "unspecified", "reserved", "possible_version_number"}


@dataclass
class Values:
    sha256: list[str]
    sha1: list[str]
    md5: list[str]
    file_names: list[str]
    domains: list[str]
    ips: list[str]
    urls: list[str]
    truncated: list[str]
    senders: list[str] = dc_field(default_factory=list)
    subjects: list[str] = dc_field(default_factory=list)
    message_ids: list[str] = dc_field(default_factory=list)

    def has_hashes(self) -> bool:
        return bool(self.sha256 or self.sha1 or self.md5)

    def has_network(self) -> bool:
        return bool(self.domains or self.ips or self.urls)


def _cap(name: str, values: list[str], truncated: list[str]) -> list[str]:
    unique = list(dict.fromkeys(v for v in values if v))
    if len(unique) > MAX_VALUES:
        truncated.append(f"{name}: first {MAX_VALUES} of {len(unique)}")
    return unique[:MAX_VALUES]


def collect(report: Any) -> Values:
    from .pipeline import walk

    reports = list(walk(report))
    truncated: list[str] = []
    names = []
    for r in reports:
        base = r.file_name.replace("\\", "/").rsplit("/", 1)[-1]
        if base:
            names.append(base)
    ips = [i["raw"] for i in report.indicators if i["type"] in ("ipv4", "ipv6")
           and not EXCLUDED_IP_TAGS & set(i.get("tags", []))]
    return Values(
        sha256=_cap("sha256", [r.hashes.get("sha256", "") for r in reports], truncated),
        sha1=_cap("sha1", [r.hashes.get("sha1", "") for r in reports], truncated),
        md5=_cap("md5", [r.hashes.get("md5", "") for r in reports], truncated),
        file_names=_cap("file names", names, truncated),
        domains=_cap("domains", [i["raw"] for i in report.indicators if i["type"] == "domain"],
                     truncated),
        ips=_cap("IP addresses", ips, truncated),
        urls=_cap("URLs", [i["raw"] for i in report.indicators if i["type"] == "url"],
                  truncated),
        truncated=truncated,
        **_email_values(reports, truncated),
    )


def _email_values(reports: list[Any], truncated: list[str]) -> dict[str, list[str]]:
    """Sender addresses, subjects and Message-IDs of every email in the triage, so the
    queries can find who else received the same message."""
    from email.utils import getaddresses

    senders, subjects, ids = [], [], []
    for r in reports:
        res = r.result("email")
        h = (res.data or {}).get("headers", {}) if res is not None else {}
        for key in ("from", "sender"):
            senders += [a.lower() for _, a in getaddresses([h.get(key, "")]) if "@" in a]
        if h.get("subject"):
            subjects.append(h["subject"])
        if h.get("message_id"):
            ids.append(h["message_id"])
    return {"senders": _cap("senders", senders, truncated),
            "subjects": _cap("subjects", subjects, truncated),
            "message_ids": _cap("message IDs", ids, truncated)}


def quote(value: str) -> str:
    """Double-quoted string literal, valid in SPL, Kusto and Kibana KQL."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _list(values: list[str], sep: str = ", ") -> str:
    return sep.join(quote(v) for v in values)


# Splunk -------------------------------------------------------------------------------

def splunk(v: Values, days: int) -> list[dict[str, str]]:
    out = []
    window = f"earliest=-{days}d"
    hashes = v.sha256 + v.sha1 + v.md5
    if hashes:
        out.append({"title": "Hashes in any indexed data (raw terms)", "kind": "hash",
                    "query": f"index=* {window} ({_list(hashes, ' OR ')})\n"
                             "| stats count min(_time) as first max(_time) as last "
                             "by index, sourcetype, host"})
        out.append({"title": "Hashes in the CIM Endpoint data model", "kind": "hash",
                    "query": "| tstats summariesonly=false count from datamodel=Endpoint.Filesystem"
                             f" where Filesystem.file_hash IN ({_list(hashes)}) {window}\n"
                             "  by Filesystem.dest Filesystem.file_name Filesystem.file_path"})
    if v.file_names:
        out.append({"title": "File names in the CIM Endpoint data model", "kind": "file",
                    "query": "| tstats summariesonly=false count from datamodel=Endpoint.Filesystem"
                             f" where Filesystem.file_name IN ({_list(v.file_names)}) {window}\n"
                             "  by Filesystem.dest Filesystem.file_name Filesystem.file_path"})
    if v.domains:
        out.append({"title": "DNS lookups of the domains (CIM Network_Resolution)",
                    "kind": "network",
                    "query": "| tstats summariesonly=false count from "
                             f"datamodel=Network_Resolution where DNS.query IN "
                             f"({_list(v.domains)}) {window}\n  by DNS.src DNS.query"})
    if v.ips:
        out.append({"title": "Connections to the IP addresses (CIM Network_Traffic)",
                    "kind": "network",
                    "query": "| tstats summariesonly=false count from datamodel=Network_Traffic"
                             f" where All_Traffic.dest IN ({_list(v.ips)}) {window}\n"
                             "  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port"})
    if v.urls:
        out.append({"title": "Requests for the URLs (CIM Web)", "kind": "network",
                    "query": "| tstats summariesonly=false count from datamodel=Web"
                             f" where Web.url IN ({_list(v.urls)}) {window}\n"
                             "  by Web.src Web.url"})
    if v.senders or v.subjects:
        cond = []
        if v.senders:
            cond.append(f"All_Email.src_user IN ({_list(v.senders)})")
        if v.subjects:
            cond.append(f"All_Email.subject IN ({_list(v.subjects)})")
        out.append({"title": "Other deliveries of this email (CIM Email)", "kind": "email",
                    "query": "| tstats summariesonly=false count from datamodel=Email"
                             f" where ({' OR '.join(cond)}) {window}\n"
                             "  by All_Email.recipient All_Email.src_user All_Email.subject"})
    if v.has_network():
        terms = v.domains + v.ips
        if terms:
            out.append({"title": "Domains and IPs in any indexed data (raw terms)",
                        "kind": "network",
                        "query": f"index=* {window} ({_list(terms, ' OR ')})\n"
                                 "| stats count by index, sourcetype, host"})
    return out


# Microsoft Sentinel / Defender XDR ----------------------------------------------------

def sentinel(v: Values, days: int) -> list[dict[str, str]]:
    out = []
    if v.has_hashes():
        out.append({"title": "Files, processes and email attachments with these hashes",
                    "kind": "hash", "query": "\n".join([
                        f"let sha256s = dynamic([{_list(v.sha256)}]);",
                        f"let sha1s = dynamic([{_list(v.sha1)}]);",
                        f"let md5s = dynamic([{_list(v.md5)}]);",
                        "union isfuzzy=true",
                        "  (DeviceFileEvents | where SHA256 in (sha256s) or SHA1 in (sha1s) "
                        "or MD5 in (md5s)),",
                        "  (DeviceProcessEvents | where SHA256 in (sha256s) or SHA1 in (sha1s) "
                        "or MD5 in (md5s)),",
                        "  (EmailAttachmentInfo | where SHA256 in (sha256s))",
                        f"| where Timestamp > ago({days}d)",
                        "| summarize count(), first = min(Timestamp), last = max(Timestamp)",
                        "    by Type, DeviceName, FileName, SHA256",
                    ])})
    if v.senders or v.subjects or v.message_ids:
        out.append({"title": "Other deliveries of this email (Defender for Office 365)",
                    "kind": "email", "query": "\n".join([
                        f"let senders = dynamic([{_list(v.senders)}]);",
                        f"let subjects = dynamic([{_list(v.subjects)}]);",
                        f"let ids = dynamic([{_list(v.message_ids)}]);",
                        "EmailEvents",
                        f"| where Timestamp > ago({days}d)",
                        "| where SenderFromAddress in~ (senders) or Subject in (subjects)"
                        " or InternetMessageId in (ids)",
                        "| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject,",
                        "    DeliveryAction, DeliveryLocation, NetworkMessageId",
                    ])})
    if (v.senders or v.subjects) and (v.urls or v.domains):
        out.append({"title": "Who else received these links (Defender for Office 365)",
                    "kind": "email", "query": "\n".join([
                        f"let urls = dynamic([{_list(v.urls)}]);",
                        f"let domains = dynamic([{_list(v.domains)}]);",
                        "EmailUrlInfo",
                        f"| where Timestamp > ago({days}d)",
                        "| where Url in (urls) or UrlDomain in~ (domains)",
                        "| join kind=inner (EmailEvents | project NetworkMessageId,"
                        " RecipientEmailAddress, Subject) on NetworkMessageId",
                        "| summarize count() by Url, RecipientEmailAddress, Subject",
                    ])})
    if v.file_names:
        out.append({"title": "Files with these names", "kind": "file", "query": "\n".join([
            f"let names = dynamic([{_list(v.file_names)}]);",
            "DeviceFileEvents",
            f"| where Timestamp > ago({days}d)",
            "| where FileName in~ (names)",
            "| summarize count(), first = min(Timestamp), last = max(Timestamp)",
            "    by DeviceName, FileName, FolderPath, SHA256",
        ])})
    if v.has_network():
        out.append({"title": "Network connections and DNS lookups", "kind": "network",
                    "query": "\n".join([
                        f"let domains = dynamic([{_list(v.domains)}]);",
                        f"let ips = dynamic([{_list(v.ips)}]);",
                        f"let urls = dynamic([{_list(v.urls)}]);",
                        "union isfuzzy=true",
                        f"  (DeviceNetworkEvents | where Timestamp > ago({days}d)",
                        "     | where RemoteIP in (ips) or RemoteUrl has_any (domains) "
                        "or RemoteUrl in (urls)",
                        "     | project TimeGenerated = Timestamp, Type, Computer = DeviceName, "
                        "Remote = coalesce(RemoteUrl, RemoteIP)),",
                        f"  (DnsEvents | where TimeGenerated > ago({days}d) "
                        "| where Name in~ (domains)",
                        "     | project TimeGenerated, Type, Computer, Remote = Name)",
                        "| summarize count(), first = min(TimeGenerated), "
                        "last = max(TimeGenerated) by Type, Computer, Remote",
                    ])})
    return out


# Elastic (Kibana KQL over ECS) --------------------------------------------------------

def _kql_or(values: list[str]) -> str:
    return "(" + " or ".join(quote(x) for x in values) + ")"


def elastic(v: Values, days: int) -> list[dict[str, str]]:
    out = []
    note = f"Set the time picker to the last {days} days."
    parts = []
    for field, values in (("sha256", v.sha256), ("sha1", v.sha1), ("md5", v.md5)):
        if values:
            parts += [f"file.hash.{field} : {_kql_or(values)}",
                      f"process.hash.{field} : {_kql_or(values)}"]
    if parts:
        out.append({"title": "Files and processes with these hashes", "kind": "hash",
                    "query": " or\n".join(parts), "note": note})
    if v.file_names:
        out.append({"title": "Files with these names", "kind": "file",
                    "query": f"file.name : {_kql_or(v.file_names)}", "note": note})
    mail = []
    if v.senders:
        mail.append(f"email.from.address : {_kql_or(v.senders)}")
    if v.subjects:
        mail.append(f"email.subject : {_kql_or(v.subjects)}")
    if v.message_ids:
        mail.append(f"email.message_id : {_kql_or([i.strip('<>') for i in v.message_ids])}")
    if mail:
        out.append({"title": "Other deliveries of this email (ECS email fields)",
                    "kind": "email", "query": " or\n".join(mail), "note": note})
    net = []
    if v.ips:
        net.append(f"destination.ip : {_kql_or(v.ips)}")
    if v.domains:
        net += [f"dns.question.name : {_kql_or(v.domains)}",
                f"url.domain : {_kql_or(v.domains)}"]
    if v.urls:
        net.append(f"url.full : {_kql_or(v.urls)}")
    if net:
        out.append({"title": "Network connections, DNS and web requests", "kind": "network",
                    "query": " or\n".join(net), "note": note})
    return out


PLATFORMS = [("splunk", "Splunk (SPL)", splunk),
             ("sentinel", "Microsoft Sentinel / Defender (KQL)", sentinel),
             ("elastic", "Elastic (Kibana KQL, ECS fields)", elastic)]


def queries(values: Values, days: int) -> dict[str, Any]:
    return {key: {"title": title, "queries": fn(values, days)} for key, title, fn in PLATFORMS}


def build(report: Any, days: int) -> dict[str, Any]:
    values = collect(report)
    return {"days": days, "truncated": values.truncated, "values": asdict(values),
            "platforms": queries(values, days)}


def display_queries(hunt: dict[str, Any], defang_value: Callable[[str, str], str]) -> dict:
    """Queries for human-readable output: same syntax, indicator values defanged.
    Hashes are untouched; field names and query syntax are never rewritten."""
    v = dict(hunt["values"])
    v["domains"] = [defang_value("domain", x) for x in v["domains"]]
    v["urls"] = [defang_value("url", x) for x in v["urls"]]
    v["ips"] = [defang_value("ipv6" if ":" in x else "ipv4", x) for x in v["ips"]]
    v["file_names"] = [defang_value("text", x) for x in v["file_names"]]
    v["senders"] = [defang_value("email", x) for x in v.get("senders", [])]
    v["subjects"] = [defang_value("text", x) for x in v.get("subjects", [])]
    v["message_ids"] = [defang_value("text", x) for x in v.get("message_ids", [])]
    return queries(Values(**v), hunt["days"])


def render_text(hunt: dict[str, Any], file_name: str) -> str:
    """Paste-ready queries with raw values, for the .hunt.txt file."""
    lines = [f"# Hunt queries for {file_name}",
             "# Raw (not defanged) values: paste into your SIEM, not into tickets or chat.",
             f"# Time window: last {hunt['days']} days.", ""]
    for platform in hunt["platforms"].values():
        for q in platform["queries"]:
            lines += [f"## {platform['title']}: {q['title']}", q["query"], ""]
    return "\n".join(lines)
