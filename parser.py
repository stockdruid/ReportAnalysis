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

def _normalize_imports(imports) -> list[dict]:
    """imports가 dict({dll: {dll, imports}}) 또는 list 두 형태로 올 수 있음 → 항상 list[dict] 반환"""
    if not imports:
        return []
    if isinstance(imports, dict):
        return list(imports.values())
    if isinstance(imports, list):
        return [i if isinstance(i, dict) else {"dll": str(i), "imports": []} for i in imports]
    return []


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
            pe_imports=_normalize_imports(pe.get("imports")),
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


# ─── ThreatSummary + ReportInterpreter ───────────────────────────────────────

@dataclass
class ThreatSummary:
    verdict: str                    # "악성" / "의심" / "정상" / "분석 실패"
    verdict_color: str              # CSS 색상 코드
    behavior_tags: list[str]        # ["안티 디버깅", "정보 탈취", ...]
    key_ttps: list[tuple[str, str]] # [("T1055", "프로세스 인젝션"), ...]
    cape_summary: str               # "Unpacked PE 추출됨 — 패킹 악성코드 의심"
    one_liner: str                  # "MalScore 8/10 — 안티분석 + 정보탈취 패턴"


class ReportInterpreter:
    """
    ReportData → ThreatSummary 순수 변환기.
    UI 코드 없음. 상태 없음. summarize() 하나만 공개.
    """

    # ── 규칙 1: 시그니처 카테고리 → 한국어 행동 태그 ─────────────────────
    _CATEGORY_TAGS: dict[str, str] = {
        "antidebug":       "안티 디버깅",
        "antivm":          "가상환경 탐지",
        "antisandbox":     "샌드박스 우회",
        "antiav":          "보안 제품 비활성화",
        "infostealer":     "정보 탈취",
        "ransomware":      "랜섬웨어",
        "persistence":     "지속성 확보",
        "injection":       "프로세스 인젝션",
        "evasion":         "탐지 우회",
        "dropper":         "드로퍼",
        "network":         "네트워크 통신",
        "packer":          "패킹/난독화",
        "exploit":         "취약점 악용",
        "keylogger":       "키로거",
        "rootkit":         "루트킷",
        "banker":          "뱅킹 악성코드",
        "rat":             "원격 접근 트로이목마",
        "spyware":         "스파이웨어",
        "bootkit":         "부트킷",
        "credential":      "자격증명 탈취",
        "downloader":      "다운로더",
        "worm":            "웜",
        "backdoor":        "백도어",
        "trojan":          "트로이목마",
        "stealth":         "은닉",
        "uac":             "UAC 우회",
        "privilege":       "권한 상승",
        "discovery":       "시스템 정보 수집",
        "encryption":      "암호화",
        "lateral":         "내부 이동",
        "c2":              "C2 통신",
        "crypto":          "암호화폐 악용",
    }

    # ── 규칙 2: MITRE TTP ID → 기법 설명 ────────────────────────────────
    _TTP_DESC: dict[str, str] = {
        "T1027":  "난독화/패킹",
        "T1055":  "프로세스 인젝션",
        "T1082":  "시스템 정보 수집",
        "T1033":  "사용자 계정 발견",
        "T1003":  "자격증명 덤핑",
        "T1112":  "레지스트리 조작",
        "T1543":  "서비스/드라이버 등록",
        "T1562":  "보안 제품 비활성화",
        "T1059":  "명령어 실행",
        "T1547":  "시작 시 자동 실행",
        "T1083":  "파일/디렉터리 탐색",
        "T1057":  "프로세스 탐색",
        "T1012":  "레지스트리 조회",
        "T1518":  "소프트웨어 탐색",
        "T1016":  "네트워크 설정 수집",
        "T1049":  "네트워크 연결 탐색",
        "T1071":  "C2 프로토콜 사용",
        "T1095":  "Non-Application Layer 프로토콜",
        "T1105":  "파일 전송/다운로드",
        "T1140":  "파일 복호화/디코딩",
        "T1202":  "간접 명령 실행",
        "T1218":  "시스템 도구 악용",
        "T1497":  "가상화 환경 탐지",
        "T1548":  "권한 상승",
        "T1553":  "코드 서명 우회",
        "T1564":  "아티팩트 은닉",
        "T1574":  "DLL 하이재킹",
    }

    # ── 규칙 3: verdict 판정 ─────────────────────────────────────────────
    _VERDICT_MAP = [
        # (malscore 최솟값, verdict 텍스트, 색상)
        (7, "악성",      "#b91c1c"),
        (4, "의심",      "#9a3412"),
        (1, "잠재 위협", "#854d0e"),
        (0, "정상",      "#15803d"),
    ]

    @staticmethod
    def summarize(data: ReportData) -> ThreatSummary:
        # 분석 실패
        if data.malstatus.lower() in ("failed", ""):
            return ThreatSummary(
                verdict="분석 실패",
                verdict_color="#737373",
                behavior_tags=[],
                key_ttps=[],
                cape_summary="",
                one_liner="샌드박스 분석이 완료되지 않았습니다.",
            )

        verdict, verdict_color = ReportInterpreter._get_verdict(data.malscore)
        behavior_tags = ReportInterpreter._get_behavior_tags(data.signatures)
        key_ttps = ReportInterpreter._get_key_ttps(data.ttps)
        cape_summary = ReportInterpreter._get_cape_summary(data.cape_payloads)
        one_liner = ReportInterpreter._build_one_liner(
            data.malscore, verdict, behavior_tags, cape_summary
        )

        return ThreatSummary(
            verdict=verdict,
            verdict_color=verdict_color,
            behavior_tags=behavior_tags,
            key_ttps=key_ttps,
            cape_summary=cape_summary,
            one_liner=one_liner,
        )

    # ── 내부 헬퍼 ────────────────────────────────────────────────────────

    @staticmethod
    def _get_verdict(malscore: int) -> tuple[str, str]:
        for min_score, label, color in ReportInterpreter._VERDICT_MAP:
            if malscore >= min_score:
                return label, color
        return "정상", "#15803d"

    @staticmethod
    def _get_behavior_tags(signatures: list[Signature]) -> list[str]:
        seen: set[str] = set()
        tags: list[str] = []
        for sig in signatures:
            for cat in sig.categories:
                # 카테고리 문자열에서 접두사 매핑 (예: "antidebug_windows" → "antidebug")
                key = next(
                    (k for k in ReportInterpreter._CATEGORY_TAGS if cat.lower().startswith(k)),
                    None
                )
                if key is None:
                    # 매핑 없으면 카테고리 자체를 태그로 (첫 글자 대문자)
                    tag = cat.replace("_", " ").title()
                else:
                    tag = ReportInterpreter._CATEGORY_TAGS[key]
                if tag not in seen:
                    seen.add(tag)
                    tags.append(tag)
        return tags

    @staticmethod
    def _get_key_ttps(ttps: list[TTP]) -> list[tuple[str, str]]:
        seen: set[str] = set()
        result: list[tuple[str, str]] = []
        for ttp in ttps:
            for tid in ttp.ttps:
                # 상위 기법만 (T1027.002 → T1027)
                parent = tid.split(".")[0]
                if parent in seen:
                    continue
                seen.add(parent)
                desc = ReportInterpreter._TTP_DESC.get(parent, "")
                result.append((parent, desc))
                if len(result) >= 6:
                    return result
        return result

    @staticmethod
    def _get_cape_summary(payloads: list[dict]) -> str:
        if not payloads:
            return ""
        types = list(dict.fromkeys(
            str(p.get("cape_type", "Unknown")) for p in payloads
        ))
        return f"{len(payloads)}개 페이로드 추출: " + ", ".join(types)

    @staticmethod
    def _build_one_liner(
        malscore: int, verdict: str, tags: list[str], cape_summary: str
    ) -> str:
        parts = [f"MalScore {malscore}/10 — {verdict}"]
        if tags:
            parts.append(" + ".join(tags[:3]))
        if cape_summary:
            parts.append(cape_summary)
        return "  |  ".join(parts)
