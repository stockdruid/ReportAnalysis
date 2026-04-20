"""
geoip.py - IP 지오로케이션 조회

오프라인(MaxMind GeoLite2) 우선 → 실패 시 온라인(ip-api.com) 폴백.
사설/예약 IP는 "Local"로 표시. 결과는 메모리에 캐시.

GeoLite2-City.mmdb 또는 GeoLite2-Country.mmdb를 같은 폴더 또는
실행 파일 폴더에 두면 자동 사용. 없으면 온라인만 사용.
"""
from __future__ import annotations

import ipaddress
import json
import os
import sys
import threading
from dataclasses import dataclass, field
from typing import Optional

try:
    import requests as _requests
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False

try:
    import geoip2.database as _geo_db
    import geoip2.errors as _geo_err
    _GEOIP2_OK = True
except ImportError:
    _GEOIP2_OK = False


# ISO 2글자 → 국기 이모지
def cc_to_flag(cc: str) -> str:
    if not cc or len(cc) != 2:
        return ""
    cc = cc.upper()
    if not cc.isalpha():
        return ""
    return chr(0x1F1E6 + ord(cc[0]) - ord('A')) + chr(0x1F1E6 + ord(cc[1]) - ord('A'))


@dataclass
class GeoInfo:
    ip: str
    country_code: str = ""   # ISO-3166 alpha-2 (e.g. "KR", "US"), "LO"=Local, ""=unknown
    country: str = ""        # 국가 영문명 또는 "Local"
    city: str = ""
    asn: str = ""            # ASN 번호 (e.g. "AS15169")
    org: str = ""            # ISP/조직명
    source: str = ""         # "offline" | "online" | "local" | "error"

    @property
    def flag(self) -> str:
        if self.country_code in ("LO", ""):
            return ""
        return cc_to_flag(self.country_code)

    @property
    def display(self) -> str:
        """테이블 셀에 표시할 짧은 문자열"""
        if not self.country_code:
            return "—"
        if self.country_code == "LO":
            return "🏠 Local"
        flag = self.flag
        return f"{flag} {self.country_code}" if flag else self.country_code


def _is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        a.is_private or a.is_loopback or a.is_link_local
        or a.is_multicast or a.is_reserved or a.is_unspecified
    )


def _candidate_db_paths() -> list[str]:
    """MaxMind .mmdb 검색 경로"""
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "GeoLite2-City.mmdb"),
        os.path.join(here, "GeoLite2-Country.mmdb"),
    ]
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(sys.executable)
        candidates.insert(0, os.path.join(exe_dir, "GeoLite2-City.mmdb"))
        candidates.insert(1, os.path.join(exe_dir, "GeoLite2-Country.mmdb"))
    return candidates


class GeoIPResolver:
    """싱글톤. 오프라인 DB → 온라인 API 순서로 조회. 결과 캐시."""

    _instance: Optional["GeoIPResolver"] = None
    _lock = threading.Lock()

    ONLINE_BATCH_URL = "http://ip-api.com/batch"
    ONLINE_BATCH_SIZE = 100
    ONLINE_TIMEOUT = 5
    ONLINE_MAX_BATCHES = 5  # 안전 상한: 최대 500 IP까지 조회

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._init()
            return cls._instance

    def _init(self) -> None:
        self._cache: dict[str, GeoInfo] = {}
        self._cache_lock = threading.Lock()
        self._reader = None
        self._reader_kind = ""  # "city" | "country"
        if _GEOIP2_OK:
            for p in _candidate_db_paths():
                if os.path.exists(p):
                    try:
                        self._reader = _geo_db.Reader(p)
                        self._reader_kind = "city" if "City" in p else "country"
                        break
                    except Exception:
                        continue

    @property
    def offline_available(self) -> bool:
        return self._reader is not None

    @property
    def online_available(self) -> bool:
        return _REQUESTS_OK

    def lookup(self, ip: str) -> GeoInfo:
        """단건 조회. 캐시→로컬→오프라인→온라인."""
        ip = (ip or "").strip()
        if not ip:
            return GeoInfo(ip="", country_code="", source="error")

        with self._cache_lock:
            if ip in self._cache:
                return self._cache[ip]

        if _is_private(ip):
            info = GeoInfo(ip=ip, country_code="LO", country="Local", source="local")
            self._put(info)
            return info

        if self._reader is not None:
            info = self._lookup_offline(ip)
            if info is not None:
                self._put(info)
                return info

        if _REQUESTS_OK:
            results = self._lookup_online_batch([ip])
            if ip in results:
                self._put(results[ip])
                return results[ip]

        info = GeoInfo(ip=ip, source="error")
        self._put(info)
        return info

    def lookup_many(self, ips: list[str]) -> dict[str, GeoInfo]:
        """대량 조회. 캐시/로컬/오프라인 우선 처리 후 미해결 IP만 온라인 배치."""
        out: dict[str, GeoInfo] = {}
        unresolved: list[str] = []

        for raw in ips:
            ip = (raw or "").strip()
            if not ip or ip in out:
                continue

            with self._cache_lock:
                if ip in self._cache:
                    out[ip] = self._cache[ip]
                    continue

            if _is_private(ip):
                info = GeoInfo(ip=ip, country_code="LO", country="Local", source="local")
                self._put(info)
                out[ip] = info
                continue

            if self._reader is not None:
                info = self._lookup_offline(ip)
                if info is not None:
                    self._put(info)
                    out[ip] = info
                    continue

            unresolved.append(ip)

        if unresolved and _REQUESTS_OK:
            print(f"[geoip] online lookup: {len(unresolved)} IPs", flush=True)
            batches_done = 0
            for i in range(0, len(unresolved), self.ONLINE_BATCH_SIZE):
                if batches_done >= self.ONLINE_MAX_BATCHES:
                    print(f"[geoip] batch cap reached ({self.ONLINE_MAX_BATCHES}); 나머지 skip", flush=True)
                    break
                chunk = unresolved[i:i + self.ONLINE_BATCH_SIZE]
                print(f"[geoip] batch {batches_done + 1}: {len(chunk)} IPs", flush=True)
                results = self._lookup_online_batch(chunk)
                print(f"[geoip] batch {batches_done + 1} done: {len(results)} resolved", flush=True)
                for ip, info in results.items():
                    self._put(info)
                    out[ip] = info
                batches_done += 1

        # 남은 미해결은 error로 마킹
        for ip in unresolved:
            if ip not in out:
                info = GeoInfo(ip=ip, source="error")
                self._put(info)
                out[ip] = info

        return out

    def _put(self, info: GeoInfo) -> None:
        with self._cache_lock:
            self._cache[info.ip] = info

    def _lookup_offline(self, ip: str) -> Optional[GeoInfo]:
        try:
            if self._reader_kind == "city":
                r = self._reader.city(ip)
                return GeoInfo(
                    ip=ip,
                    country_code=(r.country.iso_code or "").upper(),
                    country=r.country.name or "",
                    city=r.city.name or "",
                    source="offline",
                )
            else:
                r = self._reader.country(ip)
                return GeoInfo(
                    ip=ip,
                    country_code=(r.country.iso_code or "").upper(),
                    country=r.country.name or "",
                    source="offline",
                )
        except _geo_err.AddressNotFoundError:
            return GeoInfo(ip=ip, country_code="", country="Unknown", source="offline")
        except Exception:
            return None

    def _lookup_online_batch(self, ips: list[str]) -> dict[str, GeoInfo]:
        if not _REQUESTS_OK or not ips:
            return {}
        try:
            payload = [
                {"query": ip, "fields": "status,country,countryCode,city,as,org,query"}
                for ip in ips
            ]
            resp = _requests.post(
                self.ONLINE_BATCH_URL,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=self.ONLINE_TIMEOUT,
            )
            if resp.status_code != 200:
                print(f"[geoip] HTTP {resp.status_code} from ip-api.com", flush=True)
                return {}
            arr = resp.json()
        except Exception as exc:
            print(f"[geoip] online batch failed: {type(exc).__name__}: {exc}", flush=True)
            return {}

        out: dict[str, GeoInfo] = {}
        for item in arr:
            if not isinstance(item, dict):
                continue
            ip = str(item.get("query", ""))
            if not ip:
                continue
            if item.get("status") != "success":
                out[ip] = GeoInfo(ip=ip, country_code="", country="Unknown", source="online")
                continue
            out[ip] = GeoInfo(
                ip=ip,
                country_code=str(item.get("countryCode", "")).upper(),
                country=str(item.get("country", "")),
                city=str(item.get("city", "")),
                asn=str(item.get("as", "")),
                org=str(item.get("org", "")),
                source="online",
            )
        return out


def extract_ips_from_suricata(suricata: dict) -> list[str]:
    """Suricata 이벤트에서 모든 IP 추출 (중복 제거, 사설 포함)."""
    seen: set[str] = set()
    out: list[str] = []

    def _push(v) -> None:
        if not v:
            return
        s = str(v).strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)

    for e in suricata.get("alerts", []) or []:
        _push(e.get("src_ip") or e.get("src"))
        _push(e.get("dst_ip") or e.get("dest"))
    for e in suricata.get("http", []) or []:
        _push(e.get("src"))
        _push(e.get("dst"))
    for e in suricata.get("tls", []) or []:
        _push(e.get("src"))
        _push(e.get("dst"))
    for e in suricata.get("ssh", []) or []:
        _push(e.get("src"))
        _push(e.get("dst"))

    return out


def extract_ips_from_network(network: dict) -> list[str]:
    """CAPE network 섹션(hosts/dns/tcp/udp/http/https)에서 IP 추출."""
    seen: set[str] = set()
    out: list[str] = []

    def _push(v) -> None:
        if not v:
            return
        s = str(v).strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)

    # network.hosts: 보통 ["8.8.8.8", ...] 또는 [{"ip": "..."}]
    for h in network.get("hosts", []) or []:
        if isinstance(h, str):
            _push(h)
        elif isinstance(h, dict):
            _push(h.get("ip") or h.get("country_name") and h.get("ip"))

    # tcp/udp: [{"src": "...", "dst": "..."}]
    for proto in ("tcp", "udp", "icmp"):
        for c in network.get(proto, []) or []:
            if isinstance(c, dict):
                _push(c.get("src"))
                _push(c.get("dst"))

    # http/https: [{"host": "...", "dst": "..."}] — host가 도메인일 수도, IP일 수도
    for kind in ("http", "https", "http_ex", "https_ex"):
        for e in network.get(kind, []) or []:
            if isinstance(e, dict):
                _push(e.get("dst"))
                _push(e.get("src"))

    # dns answers: 응답 IP
    for q in network.get("dns", []) or []:
        if not isinstance(q, dict):
            continue
        for a in q.get("answers", []) or []:
            if isinstance(a, dict):
                _push(a.get("data"))

    # dns_servers
    for d in network.get("dns_servers", []) or []:
        _push(d)

    return out


def extract_all_ips(suricata: dict, network: dict) -> list[str]:
    """Suricata + CAPE network 양쪽에서 IP 합쳐서 반환 (중복 제거)."""
    seen: set[str] = set()
    out: list[str] = []
    for ip in extract_ips_from_suricata(suricata) + extract_ips_from_network(network):
        if ip and ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out
