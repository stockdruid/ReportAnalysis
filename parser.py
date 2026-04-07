from __future__ import annotations
from dataclasses import dataclass, field
import json


# Dataclasses

@dataclass
class PESection:
    name: str
    virtual_address: str
    virtual_size: str
    size_of_data: str
    characteristics: str
    entropy: float


@dataclass
class FileInfo:
    name: str
    size: int
    file_type: str
    md5: str
    sha1: str
    sha256: str
    sha512: str
    ssdeep: str
    tlsh: str
    crc32: str
    cape_type: str
    # PE
    imphash: str
    pe_timestamp: str
    pe_pdbpath: str
    pe_imagebase: str
    pe_entrypoint: str
    pe_osversion: str
    pe_machine_type: str
    pe_sections: list[PESection]
    pe_imports: list[dict]
    pe_exports: list[dict]
    pe_versioninfo: list[dict]
    pe_digital_signers: list[dict]
    # YARA
    yara: list[str]
    cape_yara: list[str]
    # Misc
    strings: list[str]
    virustotal: dict | None


@dataclass
class Signature:
    name: str
    description: str
    severity: int       # 1–5
    confidence: int     # 0–100
    categories: list[str]
    families: list[str]
    references: list[str]
    data: list          # raw evidence entries


@dataclass
class TTP:
    signature: str
    ttps: list[str]     # MITRE ATT&CK IDs, e.g. ["T1027", "T1027.002"]
    mbcs: list[str]     # MBC codes, e.g. ["OB0001"]


@dataclass
class AnalysisInfo:
    id: int
    version: str
    started: str
    ended: str
    duration: int       # seconds
    machine: str
    package: str
    category: str
    timeout: bool
    parent_id: int | None
    parent_md5: str


@dataclass
class ProcessCall:
    timestamp: str
    thread_id: str
    category: str
    api: str
    status: bool
    return_value: str
    arguments: list[dict]
    repeated: int


@dataclass
class Process:
    process_id: int
    process_name: str
    parent_id: int
    module_path: str
    first_seen: str
    calls: list[ProcessCall]


@dataclass
class ReportData:
    info: AnalysisInfo
    file_info: FileInfo
    malscore: int
    malstatus: str
    signatures: list[Signature]
    ttps: list[TTP]
    suricata: dict          # {alerts, dns, http, tls, ssh, files}
    network: dict
    behavior_processes: list[Process]
    cape_payloads: list[dict]
    cape_configs: list[dict]
    debug_errors: list[str]


# Parser

class ReportParser:

    @staticmethod
    def load(path: str) -> ReportData:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        return ReportParser._parse(raw)

    @staticmethod
    def _parse(raw: dict) -> ReportData:
        return ReportData(
            info=ReportParser._parse_info(raw.get("info", {})),
            file_info=ReportParser._parse_file_info(raw.get("target", {}).get("file", {})),
            malscore=int(raw.get("malscore", 0)),
            malstatus=str(raw.get("malstatus", "")),
            signatures=ReportParser._parse_signatures(raw.get("signatures", [])),
            ttps=ReportParser._parse_ttps(raw.get("ttps", [])),
            suricata=ReportParser._parse_suricata(raw.get("suricata", {})),
            network=raw.get("network", {}),
            behavior_processes=ReportParser._parse_processes(
                raw.get("behavior", {}).get("processes", [])
            ),
            cape_payloads=raw.get("CAPE", {}).get("payloads", []) or [],
            cape_configs=raw.get("CAPE", {}).get("configs", []) or [],
            debug_errors=raw.get("debug", {}).get("errors", []) or [],
        )

    # Sub-parsers

    @staticmethod
    def _parse_info(info: dict) -> AnalysisInfo:
        machine = info.get("machine") or {}
        parent = info.get("parent_sample") or {}
        return AnalysisInfo(
            id=int(info.get("id", 0)),
            version=str(info.get("version", "")),
            started=str(info.get("started", "")),
            ended=str(info.get("ended", "")),
            duration=int(info.get("duration", 0)),
            machine=str(machine.get("name", "")),
            package=str(info.get("package", "")),
            category=str(info.get("category", "")),
            timeout=bool(info.get("timeout", False)),
            parent_id=parent.get("id"),
            parent_md5=str(parent.get("md5", "")),
        )

    @staticmethod
    def _parse_file_info(f: dict) -> FileInfo:
        pe = f.get("pe") or {}
        sections = [
            PESection(
                name=str(s.get("name", "")),
                virtual_address=str(s.get("virtual_address", "")),
                virtual_size=str(s.get("virtual_size", "")),
                size_of_data=str(s.get("size_of_data", "")),
                characteristics=str(s.get("characteristics", "")),
                entropy=float(s.get("entropy", 0.0)),
            )
            for s in (pe.get("sections") or [])
        ]
        yara_names = [y.get("name", "") for y in (f.get("yara") or []) if isinstance(y, dict)]
        cape_yara_names = [y.get("name", "") for y in (f.get("cape_yara") or []) if isinstance(y, dict)]

        return FileInfo(
            name=str(f.get("name", "")),
            size=int(f.get("size", 0)),
            file_type=str(f.get("type", "")),
            md5=str(f.get("md5", "")),
            sha1=str(f.get("sha1", "")),
            sha256=str(f.get("sha256", "")),
            sha512=str(f.get("sha512", "")),
            ssdeep=str(f.get("ssdeep", "")),
            tlsh=str(f.get("tlsh", "")),
            crc32=str(f.get("crc32", "")),
            cape_type=str(f.get("cape_type", "")),
            imphash=str(pe.get("imphash", "")),
            pe_timestamp=str(pe.get("timestamp", "")),
            pe_pdbpath=str(pe.get("pdbpath", "")),
            pe_imagebase=str(pe.get("imagebase", "")),
            pe_entrypoint=str(pe.get("entrypoint", "")),
            pe_osversion=str(pe.get("osversion", "")),
            pe_machine_type=str(pe.get("machine_type", "")),
            pe_sections=sections,
            pe_imports=list(pe.get("imports") or []),
            pe_exports=list(pe.get("exports") or []),
            pe_versioninfo=list(pe.get("versioninfo") or []),
            pe_digital_signers=list(pe.get("digital_signers") or []),
            yara=yara_names,
            cape_yara=cape_yara_names,
            strings=list(f.get("strings") or []),
            virustotal=f.get("virustotal"),
        )

    @staticmethod
    def _parse_signatures(sigs: list) -> list[Signature]:
        result = []
        for s in sigs:
            if not isinstance(s, dict):
                continue
            result.append(Signature(
                name=str(s.get("name", "")),
                description=str(s.get("description", "")),
                severity=int(s.get("severity", 1)),
                confidence=int(s.get("confidence", 0)),
                categories=list(s.get("categories") or []),
                families=list(s.get("families") or []),
                references=list(s.get("references") or []),
                data=list(s.get("data") or []),
            ))
        return result

    @staticmethod
    def _parse_ttps(ttps: list) -> list[TTP]:
        result = []
        for t in ttps:
            if not isinstance(t, dict):
                continue
            result.append(TTP(
                signature=str(t.get("signature", "")),
                ttps=list(t.get("ttps") or []),
                mbcs=list(t.get("mbcs") or []),
            ))
        return result

    @staticmethod
    def _parse_suricata(s: dict) -> dict:
        return {
            "alerts": list(s.get("alerts") or []),
            "dns":    list(s.get("dns") or []),
            "http":   list(s.get("http") or []),
            "tls":    list(s.get("tls") or []),
            "ssh":    list(s.get("ssh") or []),
            "files":  list(s.get("files") or []),
        }

    @staticmethod
    def _parse_processes(procs: list) -> list[Process]:
        result = []
        for p in procs:
            if not isinstance(p, dict):
                continue
            calls = [
                ProcessCall(
                    timestamp=str(c.get("timestamp", "")),
                    thread_id=str(c.get("thread_id", "")),
                    category=str(c.get("category", "")),
                    api=str(c.get("api", "")),
                    status=bool(c.get("status", False)),
                    return_value=str(c.get("return", "")),
                    arguments=list(c.get("arguments") or []),
                    repeated=int(c.get("repeated", 0)),
                )
                for c in (p.get("calls") or [])
                if isinstance(c, dict)
            ]
            result.append(Process(
                process_id=int(p.get("process_id", 0)),
                process_name=str(p.get("process_name", "")),
                parent_id=int(p.get("parent_id", 0)),
                module_path=str(p.get("module_path", "")),
                first_seen=str(p.get("first_seen", "")),
                calls=calls,
            ))
        return result
