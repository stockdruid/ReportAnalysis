"""
main.py - CAPEv2 Report Analyzer
앱 진입점 + MainWindow + 탭 클래스 6개 (골격)

⠀⠀⠀⠀⢀⠴⣲⣯⣉⣽⣿⡛⠻⣶⠖⢒⢶⣦⣄⠀⠀⠀⠀⠀
⠀⠀⢀⡴⢁⡜⠉⠋⠉⠹⠉⠱⡄⠙⢦⣼⣾⣿⣿⣧⠀⠀⠀⠀
⠀⢀⡞⢀⡞⢀⡄⠀⠀⢀⢸⠀⠹⡀⠈⣟⠿⣿⣿⣟⣉⡇⠀⠀
⣴⣫⠀⢸⢠⣾⡇⢠⠀⢸⢰⢆⠀⡇⠀⢹⣿⣿⣿⣿⣌⡇⠀⠀
⠀⠀⢀⡼⢻⠛⢿⡾⠦⣿⣿⣿⣷⡇⠀⢸⠁⣯⣿⠛⡹⠛⣦⠀
⠀⢰⢨⠀⠈⢓⢺⢁⣀⠀⢿⢀⣼⠃⠀⣸⣠⠃⣇⡴⠁⠀⢸⡇
⠀⠘⣎⢓⢤⣄⣀⣉⡉⣁⣀⣠⣿⡆⢠⠟⠁⠀⠘⠁⠀⠀⢸⡇
⠀⠀⠈⢺⡿⠇⡀⠉⠉⠉⠉⢉⣼⡡⠋⠀⠀⢀⣴⠀⠀⣠⠟⠀
⠀⠀⠀⠀⢷⡀⢻⡶⣤⣤⠀⠀⠀⠀⣀⣤⡴⠛⡇⠀⠀⡏⠀⠀
⠀⠀⠀⠀⠈⠳⠼⠃⠀⠈⢧⡀⠀⠀⡇⠀⠀⠀⠻⣄⣀⡟⠀⠀도와줘... 도로롱...
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠶⠾⠁⠀⠀⠀⠀⠈⠉⠀⠀⠀
"""

from __future__ import annotations
import sys
import os
import re

try:
    import keyring as _keyring
    _KEYRING_OK = True
except ImportError:
    _KEYRING_OK = False

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget,
    QVBoxLayout, QHBoxLayout, QToolBar, QPushButton,
    QLabel, QFileDialog, QStatusBar, QSizePolicy,
    QScrollArea, QFrame, QSplitter, QHeaderView,
    QDialog, QLineEdit, QTextEdit, QComboBox,
)
from PyQt6.QtCore import Qt, QSize, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QGuiApplication

from parser import ReportParser, ReportData, ReportInterpreter
from widgets import (
    MalScoreBadge, EmptyState, HashCard, InfoTable, SeverityBadge,
    BLACK, WHITE, GRAY_200, GRAY_500, GRAY_50,
)


# --- 전역 스타일 --------------------------------------------------------------

APP_STYLE = f"""
QMainWindow, QWidget {{
    background: {WHITE};
    color: {BLACK};
    font-family: 'Segoe UI', system-ui, sans-serif;
    font-size: 13px;
}}
QTabWidget::pane {{
    border: none;
    border-top: 1px solid {GRAY_200};
    background: {WHITE};
}}
QTabBar::tab {{
    background: transparent;
    color: {GRAY_500};
    padding: 8px 20px;
    border: none;
    border-bottom: 2px solid transparent;
    font-size: 13px;
    font-weight: 500;
    min-width: 80px;
}}
QTabBar::tab:selected {{
    color: {BLACK};
    border-bottom: 2px solid {BLACK};
    font-weight: 600;
}}
QTabBar::tab:hover:!selected {{
    color: {BLACK};
}}
QToolBar {{
    background: {WHITE};
    border-bottom: 1px solid {GRAY_200};
    spacing: 10px;
    padding: 6px 12px;
}}
QStatusBar {{
    background: {WHITE};
    color: {GRAY_500};
    border-top: 1px solid {GRAY_200};
    font-size: 12px;
    padding: 2px 12px;
}}
QPushButton#openBtn {{
    background: {BLACK};
    color: {WHITE};
    border-radius: 50px;
    padding: 6px 18px;
    font-size: 13px;
    font-weight: 600;
    border: none;
}}
QPushButton#openBtn:hover {{
    background: #333333;
}}
QLabel#pathLabel {{
    color: {GRAY_500};
    font-size: 12px;
    font-family: Consolas, monospace;
}}
"""


# --- 탭 클래스 6개 ------------------------------------------------------------

class OverviewTab(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.addWidget(EmptyState(
            "리포트를 열어주세요",
            "파일 열기 버튼 또는 명령줄 인자로 report.json 을 지정하세요.",
        ))

    def populate(self, data: ReportData) -> None:
        _clear_layout(self._layout)

        # 스크롤 가능한 컨텐츠 영역
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        content = QWidget()
        content.setStyleSheet(f"background: {GRAY_50};")
        vbox = QVBoxLayout(content)
        vbox.setContentsMargins(24, 24, 24, 24)
        vbox.setSpacing(16)

        fi = data.file_info
        summary = ReportInterpreter.summarize(data)

        # ── 0. 위협 요약 카드 ──────────────────────────────────────────────
        threat_card = _card_widget()
        threat_card.setStyleSheet(
            f"QFrame {{ background:{WHITE}; border:2px solid {summary.verdict_color};"
            f" border-radius:8px; }}"
        )
        tc_lay = QVBoxLayout(threat_card)
        tc_lay.setContentsMargins(16, 14, 16, 14)
        tc_lay.setSpacing(10)

        # verdict + one_liner 행
        verdict_row = QHBoxLayout()
        verdict_badge = QLabel(summary.verdict)
        verdict_badge.setStyleSheet(
            f"background:{summary.verdict_color}; color:{WHITE};"
            f" border-radius:50px; padding:4px 16px;"
            f" font-size:14px; font-weight:700; border:none;"
        )
        verdict_badge.setFixedHeight(30)
        verdict_row.addWidget(verdict_badge)

        one_lbl = QLabel(summary.one_liner)
        one_lbl.setStyleSheet(f"color:{BLACK}; font-size:13px; font-weight:500;")
        one_lbl.setWordWrap(True)
        verdict_row.addWidget(one_lbl, 1)
        tc_lay.addLayout(verdict_row)

        # 행동 태그 필 배지들
        if summary.behavior_tags:
            tags_row = QHBoxLayout()
            tags_row.setSpacing(6)
            tags_row.setContentsMargins(0, 0, 0, 0)
            for tag in summary.behavior_tags[:8]:
                t_lbl = QLabel(tag)
                t_lbl.setStyleSheet(
                    f"background:{GRAY_50}; color:{BLACK};"
                    f" border:1px solid {GRAY_200}; border-radius:50px;"
                    f" padding:2px 10px; font-size:11px;"
                )
                tags_row.addWidget(t_lbl)
            tags_row.addStretch()
            tc_lay.addLayout(tags_row)

        # Key TTP 행
        if summary.key_ttps:
            ttp_row = QHBoxLayout()
            ttp_row.setSpacing(6)
            ttp_lbl_title = QLabel("TTP")
            ttp_lbl_title.setStyleSheet(
                f"color:{GRAY_500}; font-size:10px; letter-spacing:1px;"
                f" font-family:Consolas,monospace; font-weight:600;"
            )
            ttp_row.addWidget(ttp_lbl_title)
            for tid, desc in summary.key_ttps:
                text = f"{tid}" + (f"  {desc}" if desc else "")
                t_lbl = QLabel(text)
                t_lbl.setStyleSheet(
                    f"background:#eff6ff; color:#1d4ed8;"
                    f" border-radius:50px; padding:2px 10px;"
                    f" font-size:11px; font-family:Consolas,monospace;"
                )
                ttp_row.addWidget(t_lbl)
            ttp_row.addStretch()
            tc_lay.addLayout(ttp_row)

        # CAPE 요약
        if summary.cape_summary:
            cape_lbl = QLabel(summary.cape_summary)
            cape_lbl.setStyleSheet(
                f"color:{GRAY_500}; font-size:12px; font-style:italic;"
            )
            tc_lay.addWidget(cape_lbl)

        vbox.addWidget(threat_card)

        # ── 1. 파일 요약 카드 ──────────────────────────────────────────────
        summary_card, s_lay = _card_with_vbox()
        title = QLabel(fi.name if fi.name else "Unknown")
        title.setStyleSheet(f"color:{BLACK}; font-size:18px; font-weight:700;")
        s_lay.addWidget(title)

        s_lay.addLayout(_meta_row([
            ("크기", f"{fi.size:,} bytes"),
            ("타입", fi.file_type[:60] if fi.file_type else "—"),
            ("패키지", data.info.package),
            ("분석 머신", data.info.machine),
            ("소요 시간", f"{data.info.duration}초"),
        ]))
        s_lay.addLayout(_meta_row(
            [
                ("시작", data.info.started),
                ("종료", data.info.ended),
                ("상태", data.malstatus),
                ("CAPE 탐지", fi.cape_type if fi.cape_type else "—"),
            ],
            val_style=f"color:{BLACK}; font-size:13px;",
        ))
        vbox.addWidget(summary_card)

        # ── 2. 해시 카드 ───────────────────────────────────────────────────
        hash_items = [
            ("MD5",     fi.md5),
            ("SHA1",    fi.sha1),
            ("SHA256",  fi.sha256),
            ("SHA512",  fi.sha512),
            ("SSDeep",  fi.ssdeep),
            ("TLSH",    fi.tlsh),
            ("CRC32",   fi.crc32),
            ("ImpHash", fi.imphash),
        ]
        vbox.addWidget(HashCard("파일 해시", hash_items))

        # ── 3. PE 정보 ─────────────────────────────────────────────────────
        pe_card, pe_lay = _card_with_vbox(spacing=12)

        pe_title = QLabel("PE 정보")
        pe_title.setStyleSheet(f"color:{BLACK}; font-size:14px; font-weight:700;")
        pe_lay.addWidget(pe_title)

        pe_lay.addLayout(_meta_row(
            [
                ("Timestamp",  fi.pe_timestamp),
                ("ImageBase",  fi.pe_imagebase),
                ("EntryPoint", fi.pe_entrypoint),
                ("OS Version", fi.pe_osversion),
                ("Machine",    fi.pe_machine_type),
            ],
            val_style=_MONO_VAL_STYLE,
        ))

        if fi.pe_pdbpath:
            pe_lay.addLayout(_kv_inline_row("PDB", fi.pe_pdbpath, key_width=60))

        # 섹션 테이블
        if fi.pe_sections:
            pe_lay.addWidget(_section_label("섹션"))
            sec_table = InfoTable(["이름", "VA", "크기", "특성", "엔트로피"])
            _fixed_height_table(sec_table, len(fi.pe_sections))
            for sec in fi.pe_sections:
                sec_table.add_row([
                    sec.name, sec.virtual_address, sec.size_of_data,
                    sec.characteristics, f"{sec.entropy:.2f}",
                ])
            sec_table.fit_columns()
            pe_lay.addWidget(sec_table)

        # VersionInfo
        if fi.pe_versioninfo:
            pe_lay.addWidget(_section_label("Version Info"))
            ver_table = InfoTable(["Key", "Value"])
            _fixed_height_table(ver_table, len(fi.pe_versioninfo))
            for entry in fi.pe_versioninfo:
                ver_table.add_row([
                    str(entry.get("name", "")),
                    str(entry.get("value", "")),
                ])
            ver_table.fit_columns()
            pe_lay.addWidget(ver_table)

        # Imports
        if fi.pe_imports:
            pe_lay.addWidget(_section_label(f"임포트 DLL ({len(fi.pe_imports)}개)"))
            imp_table = InfoTable(["DLL", "함수 수"])
            _fixed_height_table(imp_table, len(fi.pe_imports), cap=10)
            for imp in fi.pe_imports:
                imp_table.add_row([
                    str(imp.get("dll", "")),
                    str(len(imp.get("imports", []))),
                ])
            imp_table.fit_columns()
            pe_lay.addWidget(imp_table)

        # Digital Signers
        if fi.pe_digital_signers:
            pe_lay.addWidget(_section_label("디지털 서명"))
            for signer in fi.pe_digital_signers:
                s = QLabel(str(signer))
                s.setStyleSheet(f"color:{BLACK}; font-size:12px;")
                s.setWordWrap(True)
                pe_lay.addWidget(s)

        if not fi.pe_sections and not fi.pe_versioninfo and not fi.pe_imports:
            pe_lay.addWidget(EmptyState("PE 정보 없음"))

        vbox.addWidget(pe_card)

        # ── 4. YARA 매치 ───────────────────────────────────────────────────
        all_yara = fi.yara + fi.cape_yara
        if all_yara:
            yara_card, y_lay = _card_with_vbox(spacing=8)
            y_title = QLabel(f"YARA 매치 ({len(all_yara)}개)")
            y_title.setStyleSheet(f"color:{BLACK}; font-size:14px; font-weight:700;")
            y_lay.addWidget(y_title)

            yara_table = InfoTable(["Rule", "소스"])
            _fixed_height_table(yara_table, len(all_yara))
            for name in fi.yara:
                yara_table.add_row([name, "YARA"])
            for name in fi.cape_yara:
                yara_table.add_row([name, "CAPE YARA"])
            yara_table.fit_columns()
            y_lay.addWidget(yara_table)
            vbox.addWidget(yara_card)

        # ── 5. VirusTotal ──────────────────────────────────────────────────
        vt = fi.virustotal
        if vt and isinstance(vt, dict) and not vt.get("error"):
            vt_card, vt_lay = _card_with_vbox(spacing=8)
            vt_title = QLabel("VirusTotal")
            vt_title.setStyleSheet(f"color:{BLACK}; font-size:14px; font-weight:700;")
            vt_lay.addWidget(vt_title)
            positives = vt.get("positives", 0)
            total_vt  = vt.get("total", 0)
            ratio_lbl = QLabel(f"{positives} / {total_vt} 엔진 탐지")
            ratio_lbl.setStyleSheet(
                f"color:{'#b91c1c' if positives > 0 else '#15803d'};"
                f" font-size:16px; font-weight:700;"
            )
            vt_lay.addWidget(ratio_lbl)
            vbox.addWidget(vt_card)


        _MAX_STRINGS = 200
        if fi.strings:
            str_card, st_lay = _card_with_vbox(spacing=8)
            clipped = len(fi.strings) > _MAX_STRINGS
            title_text = (
                f"Strings ({_MAX_STRINGS}/{len(fi.strings)}개 표시)"
                if clipped else f"Strings ({len(fi.strings)}개)"
            )
            st_title = QLabel(title_text)
            st_title.setStyleSheet(f"color:{BLACK}; font-size:14px; font-weight:700;")
            st_lay.addWidget(st_title)

            str_table = InfoTable(["String"])
            _fixed_height_table(str_table, min(len(fi.strings), _MAX_STRINGS), cap=_MAX_STRINGS)
            for s in fi.strings[:_MAX_STRINGS]:
                str_table.add_row([s])
            st_lay.addWidget(str_table)
            vbox.addWidget(str_card)

        vbox.addStretch()
        scroll.setWidget(content)
        self._layout.addWidget(scroll)


class SignaturesTab(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._sigs: list = []
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)
        self._layout.addWidget(EmptyState("리포트를 열어주세요"))

    def populate(self, data: ReportData) -> None:
        _clear_layout(self._layout)
        self._sigs = data.signatures

        if not self._sigs:
            self._layout.addWidget(EmptyState("시그니처 없음", "이 리포트에서 탐지된 시그니처가 없습니다."))
            return

        # ── 필터 바 ──────────────────────────────────────────────────────
        filter_bar = QWidget()
        filter_bar.setStyleSheet(f"background:{WHITE}; border-bottom:1px solid {GRAY_200};")
        fb_lay = QHBoxLayout(filter_bar)
        fb_lay.setContentsMargins(16, 8, 16, 8)
        fb_lay.setSpacing(8)

        count_lbl = QLabel(f"시그니처 {len(self._sigs)}개")
        count_lbl.setStyleSheet(f"color:{GRAY_500}; font-size:12px;")
        fb_lay.addWidget(count_lbl)
        fb_lay.addStretch()

        filter_lbl = QLabel("심각도 필터:")
        filter_lbl.setStyleSheet(f"color:{GRAY_500}; font-size:12px;")
        fb_lay.addWidget(filter_lbl)

        # 필터 버튼 ("전체" + 1~5)
        self._filter_btns: dict[str, QPushButton] = {}
        for key, label in [("ALL", "전체"), ("1","Info"), ("2","Low"), ("3","Medium"), ("4","High"), ("5","Critical")]:
            btn = QPushButton(label)
            btn.setCheckable(True)
            btn.setChecked(key == "ALL")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setStyleSheet(self._btn_style(key, checked=(key == "ALL")))
            btn.clicked.connect(lambda _, k=key: self._apply_filter(k))
            self._filter_btns[key] = btn
            fb_lay.addWidget(btn)

        self._layout.addWidget(filter_bar)

        # ── 본문: 좌(테이블) + 우(상세 패널) 스플리터 ──────────────────
        splitter = _make_splitter()

        # 좌: 시그니처 테이블
        self._table = InfoTable(["", "이름", "설명", "카테고리", "신뢰도"])
        self._table.setColumnWidth(0, 80)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self._table.itemSelectionChanged.connect(self._on_select)
        splitter.addWidget(self._table)

        # 우: 상세 패널
        self._detail = QScrollArea()
        self._detail.setWidgetResizable(True)
        self._detail.setFrameShape(QFrame.Shape.NoFrame)
        self._detail.setMinimumWidth(320)
        self._detail.setStyleSheet(f"background:{GRAY_50}; border:none;")
        self._detail_content = QWidget()
        self._detail_content.setStyleSheet(f"background:{GRAY_50};")
        dc_lay = QVBoxLayout(self._detail_content)
        dc_lay.addWidget(EmptyState("시그니처를 선택하세요"))
        self._detail.setWidget(self._detail_content)
        splitter.addWidget(self._detail)

        splitter.setSizes([620, 400])
        self._layout.addWidget(splitter)

        self._fill_table(self._sigs)

    # ── 테이블 채우기 ─────────────────────────────────────────────────────

    def _fill_table(self, sigs: list) -> None:
        self._table.setRowCount(0)
        for sig in sigs:
            row = self._table.add_row([
                "",
                sig.name,
                sig.description,
                ", ".join(sig.categories),
                f"{sig.confidence}%",
            ])
            badge = SeverityBadge(sig.severity)
            self._table.set_widget_in_cell(row, 0, badge)
            self._table.setRowHeight(row, 36)
        self._table.fit_columns()
        self._table.setColumnWidth(2, 300)

    # ── 필터 적용 ─────────────────────────────────────────────────────────

    def _apply_filter(self, key: str) -> None:
        for k, btn in self._filter_btns.items():
            checked = (k == key)
            btn.setChecked(checked)
            btn.setStyleSheet(self._btn_style(k, checked))

        if key == "ALL":
            self._fill_table(self._sigs)
        else:
            sev = int(key)
            self._fill_table([s for s in self._sigs if s.severity == sev])

        # 상세 패널 초기화
        _clear_layout(self._detail_content.layout())
        self._detail_content.layout().addWidget(EmptyState("시그니처를 선택하세요"))

    # ── 행 선택 → 상세 패널 갱신 ─────────────────────────────────────────

    def _on_select(self) -> None:
        rows = self._table.selectedItems()
        if not rows:
            return
        row_idx = self._table.currentRow()
        # 현재 필터 상태에서 표시 중인 sig 매핑
        sig_name = self._table.item(row_idx, 1)
        if sig_name is None:
            return
        name = sig_name.text()
        sig = next((s for s in self._sigs if s.name == name), None)
        if sig is None:
            return
        self._show_detail(sig)

    def _show_detail(self, sig) -> None:
        layout = self._detail_content.layout()
        _clear_layout(layout)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # 헤더
        header = QHBoxLayout()
        badge = SeverityBadge(sig.severity)
        header.addWidget(badge)
        name_lbl = QLabel(sig.name)
        name_lbl.setStyleSheet(f"color:{BLACK}; font-size:14px; font-weight:700;")
        name_lbl.setWordWrap(True)
        header.addWidget(name_lbl, 1)
        layout.addLayout(header)

        desc = QLabel(sig.description)
        desc.setStyleSheet(f"color:{GRAY_500}; font-size:13px;")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        # 메타
        meta_pairs = []
        if sig.categories:
            meta_pairs.append(("카테고리", ", ".join(sig.categories)))
        if sig.families:
            meta_pairs.append(("패밀리", ", ".join(sig.families)))
        meta_pairs.append(("신뢰도", f"{sig.confidence}%"))

        for k, v in meta_pairs:
            layout.addLayout(_kv_inline_row(k, v))

        # 구분선
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet(f"color:{GRAY_200};")
        layout.addWidget(line)

        # 증거 데이터
        if sig.data:
            ev_lbl = QLabel(f"증거 ({len(sig.data)}개)")
            ev_lbl.setStyleSheet(f"color:{BLACK}; font-size:13px; font-weight:600;")
            layout.addWidget(ev_lbl)
            for entry in sig.data:
                ev_card, ev_lay = _card_with_vbox(margins=(10, 8, 10, 8), spacing=4)
                pairs = entry.items() if isinstance(entry, dict) else [("값", entry)]
                for ek, ev in pairs:
                    ev_row = QHBoxLayout()
                    ek_lbl = QLabel(str(ek).upper())
                    ek_lbl.setFixedWidth(80)
                    ek_lbl.setStyleSheet(_MONO_KEY_STYLE)
                    ev_val = QLabel(self._fmt_evidence(ev))
                    ev_val.setStyleSheet(_MONO_VAL_STYLE)
                    ev_val.setWordWrap(True)
                    ev_row.addWidget(ek_lbl)
                    ev_row.addWidget(ev_val, 1)
                    ev_lay.addLayout(ev_row)
                layout.addWidget(ev_card)
        else:
            layout.addWidget(EmptyState("증거 데이터 없음"))

        # 참조 링크
        if sig.references:
            ref_lbl = QLabel("참조")
            ref_lbl.setStyleSheet(f"color:{BLACK}; font-size:13px; font-weight:600;")
            layout.addWidget(ref_lbl)
            for ref in sig.references:
                r_lbl = QLabel(f"• {ref}")
                r_lbl.setStyleSheet(f"color:#2563eb; font-size:12px;")
                r_lbl.setWordWrap(True)
                layout.addWidget(r_lbl)

        layout.addStretch()

    @staticmethod
    def _fmt_evidence(val) -> str:
        if isinstance(val, dict):
            return "  ".join(f"{k}: {v}" for k, v in val.items())
        if isinstance(val, list):
            return ", ".join(str(i) for i in val[:10])
        return str(val)

    @staticmethod
    def _btn_style(key: str, checked: bool) -> str:
        from widgets import SEVERITY_COLORS
        if checked:
            if key == "ALL":
                bg, fg = BLACK, WHITE
            else:
                sev = int(key)
                bg, fg = SEVERITY_COLORS.get(sev, (BLACK, WHITE))
            return (
                f"QPushButton {{ background:{bg}; color:{fg};"
                f" border-radius:50px; padding:3px 12px;"
                f" font-size:12px; font-weight:600; border:none; }}"
            )
        return (
            f"QPushButton {{ background:transparent; color:{GRAY_500};"
            f" border-radius:50px; padding:3px 12px;"
            f" font-size:12px; border:1px solid {GRAY_200}; }}"
            f"QPushButton:hover {{ color:{BLACK}; border-color:{BLACK}; }}"
        )


class ATTACKTab(QWidget):
    # MITRE ATT&CK 기법 링크 베이스
    _MITRE_BASE = "https://attack.mitre.org/techniques/"
    # TTP ID 형식 검증 — 리포트 데이터 신뢰 불가
    _TTP_MAIN_RE = re.compile(r'^T\d{4}$')
    _TTP_SUB_RE  = re.compile(r'^\d{3}$')

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)
        self._layout.addWidget(EmptyState("리포트를 열어주세요"))

    def populate(self, data: ReportData) -> None:
        _clear_layout(self._layout)

        if not data.ttps:
            self._layout.addWidget(EmptyState("TTP 없음", "이 리포트에서 탐지된 ATT&CK TTP가 없습니다."))
            return

        # TTP ID 단위로 행 펼치기 (하나의 signature가 여러 TTP를 가질 수 있음)
        rows: list[tuple[str, str, str, str]] = []  # (ttp_id, sub_id, signature, mbcs)
        for ttp in data.ttps:
            mbcs_str = ", ".join(ttp.mbcs) if ttp.mbcs else "—"
            if ttp.ttps:
                for tid in ttp.ttps:
                    # T1027.002 → 상위 T1027 / 하위 .002
                    parts = tid.split(".", 1)
                    main_id = parts[0]
                    sub_id  = parts[1] if len(parts) > 1 else ""
                    rows.append((main_id, sub_id, ttp.signature, mbcs_str))
            else:
                rows.append(("—", "", ttp.signature, mbcs_str))

        self._layout.addWidget(_header_bar(
            f"ATT&CK TTP  {len(rows)}개 (클릭 시 MITRE 링크 열기)"
        ))

        # 테이블
        table = InfoTable(["TTP ID", "하위 기법", "연결 시그니처", "MBCS"])
        table.setStyleSheet(table.styleSheet() + "QTableWidget::item { cursor: pointer; }")
        table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        table.cellClicked.connect(lambda r, _c: self._open_mitre(table, r))
        table.setCursor(Qt.CursorShape.PointingHandCursor)

        for main_id, sub_id, sig_name, mbcs_str in rows:
            row_idx = table.add_row([main_id, sub_id if sub_id else "—", sig_name, mbcs_str])
            table.setRowHeight(row_idx, 34)

            # TTP ID 셀 — 파란 링크 스타일
            id_item = table.item(row_idx, 0)
            if id_item and main_id != "—":
                id_item.setForeground(QColor("#2563eb"))
                font = id_item.font()
                font.setUnderline(True)
                id_item.setFont(font)

        table.fit_columns()
        self._layout.addWidget(table)

    def _open_mitre(self, table: InfoTable, row: int) -> None:
        import webbrowser
        id_item = table.item(row, 0)
        sub_item = table.item(row, 1)
        if id_item is None or id_item.text() == "—":
            return
        main_id = id_item.text()          # 예: T1027
        sub_id  = sub_item.text() if sub_item and sub_item.text() != "—" else ""
        # 악성 리포트가 TTP ID에 임의 URL/경로 삽입하는 것을 방지
        if not self._TTP_MAIN_RE.match(main_id):
            return
        if sub_id and not self._TTP_SUB_RE.match(sub_id):
            return
        # T1027 → /T1027/  |  T1027 + 002 → /T1027/002/
        path = main_id + ("/" + sub_id + "/" if sub_id else "/")
        webbrowser.open(self._MITRE_BASE + path)


class NetworkTab(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)
        self._layout.addWidget(EmptyState("리포트를 열어주세요"))

    def populate(self, data: ReportData) -> None:
        _clear_layout(self._layout)
        s = data.suricata
        total = sum(len(v) for v in s.values())

        self._layout.addWidget(_header_bar(f"Suricata 이벤트  {total}개"))

        # 서브탭
        sub = QTabWidget()
        sub.setDocumentMode(True)
        sub.setStyleSheet(f"""
            QTabBar::tab {{
                background: transparent; color: {GRAY_500};
                padding: 6px 16px; border: none;
                border-bottom: 2px solid transparent;
                font-size: 12px;
            }}
            QTabBar::tab:selected {{
                color: {BLACK}; border-bottom: 2px solid {BLACK};
                font-weight: 600;
            }}
            QTabBar::tab:hover:!selected {{ color: {BLACK}; }}
            QTabWidget::pane {{ border: none; background: {WHITE}; }}
        """)

        sub.addTab(self._make_alerts_tab(s["alerts"]),  f"Alerts ({len(s['alerts'])})")
        sub.addTab(self._make_dns_tab(s["dns"]),        f"DNS ({len(s['dns'])})")
        sub.addTab(self._make_http_tab(s["http"]),      f"HTTP ({len(s['http'])})")
        sub.addTab(self._make_tls_tab(s["tls"]),        f"TLS ({len(s['tls'])})")
        sub.addTab(self._make_ssh_tab(s["ssh"]),        f"SSH ({len(s['ssh'])})")
        sub.addTab(self._make_files_tab(s["files"]),    f"Files ({len(s['files'])})")

        self._layout.addWidget(sub)

    # ── 서브탭 빌더 ──────────────────────────────────────────────────────────

    @staticmethod
    def _make_alerts_tab(items: list) -> QWidget:
        if not items:
            return EmptyState("Suricata Alert 없음")
        t = InfoTable(["Timestamp", "Category", "Signature", "Severity", "Src IP", "Dst IP", "Proto"])
        t.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        for e in items:
            t.add_row([
                str(e.get("timestamp", "")),
                str(e.get("category", "")),
                str(e.get("signature", "")),
                str(e.get("severity", "")),
                str(e.get("src_ip",   e.get("src", ""))),
                str(e.get("dst_ip",   e.get("dest", ""))),
                str(e.get("proto", "")),
            ])
        t.fit_columns()
        return t

    @staticmethod
    def _make_dns_tab(items: list) -> QWidget:
        if not items:
            return EmptyState("DNS 요청 없음")
        t = InfoTable(["Request", "Type", "Answers"])
        t.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        t.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        for e in items:
            answers = e.get("answers", [])
            ans_str = ", ".join(
                a.get("data", str(a)) if isinstance(a, dict) else str(a)
                for a in answers
            ) if answers else "—"
            t.add_row([
                str(e.get("request", "")),
                str(e.get("type", "")),
                ans_str,
            ])
        t.fit_columns()
        return t

    @staticmethod
    def _make_http_tab(items: list) -> QWidget:
        if not items:
            return EmptyState("HTTP 요청 없음")
        t = InfoTable(["Timestamp", "Src", "Dst", "URI", "Method", "Status"])
        t.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        for e in items:
            src = f"{e.get('src', '')}:{e.get('sport', '')}"
            dst = f"{e.get('dst', '')}:{e.get('dport', '')}"
            t.add_row([
                str(e.get("timestamp", "")),
                src, dst,
                str(e.get("uri", "")),
                str(e.get("method", "")),
                str(e.get("status", "")),
            ])
        t.fit_columns()
        return t

    @staticmethod
    def _make_tls_tab(items: list) -> QWidget:
        if not items:
            return EmptyState("TLS 세션 없음")
        t = InfoTable(["Timestamp", "Src", "Dst", "Version", "SNI", "Subject"])
        t.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        for e in items:
            t.add_row([
                str(e.get("timestamp", "")),
                str(e.get("src", "")),
                str(e.get("dst", "")),
                str(e.get("version", "")),
                str(e.get("sni", "")),
                str(e.get("subject", "")),
            ])
        t.fit_columns()
        return t

    @staticmethod
    def _make_ssh_tab(items: list) -> QWidget:
        if not items:
            return EmptyState("SSH 세션 없음")
        t = InfoTable(["Timestamp", "Src", "Dst", "Client", "Server"])
        t.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        for e in items:
            t.add_row([
                str(e.get("timestamp", "")),
                str(e.get("src", "")),
                str(e.get("dst", "")),
                str(e.get("client", "")),
                str(e.get("server", "")),
            ])
        t.fit_columns()
        return t

    @staticmethod
    def _make_files_tab(items: list) -> QWidget:
        if not items:
            return EmptyState("캡처된 파일 없음")
        t = InfoTable(["Filename", "Magic", "MD5", "SHA256", "Size"])
        t.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for e in items:
            t.add_row([
                str(e.get("filename", e.get("name", ""))),
                str(e.get("magic", "")),
                str(e.get("md5", "")),
                str(e.get("sha256", "")),
                str(e.get("size", "")),
            ])
        t.fit_columns()
        return t


class BehaviorTab(QWidget):
    _MAX_CALLS = 1000   # 테이블 최대 표시 행 (성능)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._procs: list = []
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)
        self._layout.addWidget(EmptyState("리포트를 열어주세요"))

    def populate(self, data: ReportData) -> None:
        _clear_layout(self._layout)
        self._procs = data.behavior_processes

        if not self._procs:
            self._layout.addWidget(EmptyState("프로세스 없음", "행동 분석 데이터가 없습니다."))
            return

        total_calls = sum(len(p.calls) for p in self._procs)

        self._layout.addWidget(_header_bar(
            f"프로세스 {len(self._procs)}개  |  API 호출 {total_calls:,}개"
        ))

        # ── 좌(프로세스 목록) + 우(API 호출 테이블) 스플리터 ────────────
        splitter = _make_splitter()

        # 좌: 프로세스 목록 테이블
        self._proc_table = InfoTable(["PID", "프로세스명", "부모 PID", "API 호출"])
        self._proc_table.setMaximumWidth(380)
        self._proc_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        for proc in self._procs:
            row = self._proc_table.add_row([
                str(proc.process_id),
                proc.process_name,
                str(proc.parent_id),
                f"{len(proc.calls):,}",
            ])
            self._proc_table.setRowHeight(row, 34)
        self._proc_table.fit_columns()
        self._proc_table.itemSelectionChanged.connect(self._on_proc_select)
        splitter.addWidget(self._proc_table)

        # 우: API 호출 테이블 + 정보
        right = QWidget()
        right.setStyleSheet(f"background:{WHITE};")
        right_lay = QVBoxLayout(right)
        right_lay.setContentsMargins(0, 0, 0, 0)
        right_lay.setSpacing(0)

        self._call_info = QLabel("프로세스를 선택하세요")
        self._call_info.setStyleSheet(
            f"color:{GRAY_500}; font-size:12px; padding:6px 12px;"
            f" background:{WHITE}; border-bottom:1px solid {GRAY_200};"
        )
        right_lay.addWidget(self._call_info)

        self._call_table = InfoTable(["Timestamp", "Category", "API", "Status", "Return", "인자"])
        self._call_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch
        )
        self._call_table.horizontalHeader().setSectionResizeMode(
            5, QHeaderView.ResizeMode.Stretch
        )
        right_lay.addWidget(self._call_table)
        splitter.addWidget(right)

        splitter.setSizes([380, 900])
        self._layout.addWidget(splitter)

        # 첫 번째 프로세스 자동 선택
        if self._procs:
            self._proc_table.selectRow(0)

    # ── 프로세스 선택 → API 호출 테이블 갱신 ─────────────────────────────

    def _on_proc_select(self) -> None:
        row = self._proc_table.currentRow()
        if row < 0 or row >= len(self._procs):
            return
        proc = self._procs[row]
        calls = proc.calls
        limited = calls[:self._MAX_CALLS]
        clipped = len(calls) > self._MAX_CALLS

        self._call_info.setText(
            f"{proc.process_name}  (PID {proc.process_id})  —  "
            f"API 호출 {len(calls):,}개"
            + (f"  [상위 {self._MAX_CALLS:,}개만 표시]" if clipped else "")
        )

        self._call_table.setRowCount(0)
        for c in limited:
            args_str = "  ".join(
                f"{a['name']}={a['value']}" for a in c.arguments if isinstance(a, dict)
            ) if c.arguments else ""
            rep = f" ×{c.repeated}" if c.repeated else ""
            row_idx = self._call_table.add_row([
                c.timestamp.split(",")[0],   # 밀리초 제거
                c.category,
                c.api + rep,
                "OK" if c.status else "FAIL",
                c.return_value,
                args_str,
            ])
            # FAIL 행 — 연한 빨강 배경
            if not c.status:
                for col in range(self._call_table.columnCount()):
                    item = self._call_table.item(row_idx, col)
                    if item:
                        item.setBackground(QColor("#fee2e2"))
            self._call_table.setRowHeight(row_idx, 28)

        self._call_table.fit_columns()


class CAPETab(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._payloads: list = []
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)
        self._layout.addWidget(EmptyState("리포트를 열어주세요"))

    def populate(self, data: ReportData) -> None:
        _clear_layout(self._layout)
        self._payloads = data.cape_payloads

        if not data.cape_payloads and not data.cape_configs:
            self._layout.addWidget(EmptyState("CAPE 추출 결과 없음", "추출된 페이로드나 설정값이 없습니다."))
            return

        self._layout.addWidget(_header_bar(
            f"페이로드 {len(data.cape_payloads)}개  |  설정 {len(data.cape_configs)}개"
        ))

        # ── 스플리터: 좌(페이로드 목록) + 우(상세) ───────────────────────
        splitter = _make_splitter()

        # 좌: 페이로드 + 설정 목록
        left = QWidget()
        left.setStyleSheet(f"background:{WHITE};")
        left_lay = QVBoxLayout(left)
        left_lay.setContentsMargins(0, 0, 0, 0)
        left_lay.setSpacing(0)

        # 페이로드 목록
        if data.cape_payloads:
            pay_lbl = QLabel(f"  페이로드 ({len(data.cape_payloads)}개)")
            pay_lbl.setStyleSheet(
                f"color:{GRAY_500}; font-size:11px; font-weight:600;"
                f" letter-spacing:1px; padding:8px 16px 4px;"
                f" background:{GRAY_50}; border-bottom:1px solid {GRAY_200};"
            )
            left_lay.addWidget(pay_lbl)

            self._payload_table = InfoTable(["CAPE 타입", "프로세스", "크기", "MD5"])
            self._payload_table.horizontalHeader().setSectionResizeMode(
                0, QHeaderView.ResizeMode.Stretch
            )
            for p in data.cape_payloads:
                row = self._payload_table.add_row([
                    str(p.get("cape_type", "Unknown")),
                    str(p.get("process_name", "")),
                    f"{p.get('size', 0):,} B",
                    str(p.get("md5", "")),
                ])
                self._payload_table.setRowHeight(row, 34)
            self._payload_table.fit_columns()
            self._payload_table.itemSelectionChanged.connect(self._on_payload_select)
            left_lay.addWidget(self._payload_table)

        # 설정 목록
        if data.cape_configs:
            cfg_lbl = QLabel(f"  설정값 ({len(data.cape_configs)}개)")
            cfg_lbl.setStyleSheet(
                f"color:{GRAY_500}; font-size:11px; font-weight:600;"
                f" letter-spacing:1px; padding:8px 16px 4px;"
                f" background:{GRAY_50}; border-bottom:1px solid {GRAY_200};"
            )
            left_lay.addWidget(cfg_lbl)

            cfg_table = InfoTable(["악성코드 패밀리", "키", "값"])
            cfg_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
            for cfg in data.cape_configs:
                if isinstance(cfg, dict):
                    for family, entries in cfg.items():
                        if isinstance(entries, dict):
                            for k, v in entries.items():
                                cfg_table.add_row([family, str(k), str(v)])
                        else:
                            cfg_table.add_row([family, "", str(entries)])
            cfg_table.fit_columns()
            left_lay.addWidget(cfg_table)

        splitter.addWidget(left)

        # 우: 상세 패널
        self._detail = QScrollArea()
        self._detail.setWidgetResizable(True)
        self._detail.setFrameShape(QFrame.Shape.NoFrame)
        self._detail.setStyleSheet(f"background:{GRAY_50}; border:none;")
        self._detail_content = QWidget()
        self._detail_content.setStyleSheet(f"background:{GRAY_50};")
        dc_lay = QVBoxLayout(self._detail_content)
        dc_lay.setContentsMargins(16, 16, 16, 16)
        dc_lay.addWidget(EmptyState("페이로드를 선택하세요"))
        self._detail.setWidget(self._detail_content)
        splitter.addWidget(self._detail)

        splitter.setSizes([500, 480])
        self._layout.addWidget(splitter)

        # 첫 번째 페이로드 자동 선택
        if data.cape_payloads and hasattr(self, "_payload_table"):
            self._payload_table.selectRow(0)

    # ── 페이로드 선택 → 상세 패널 ─────────────────────────────────────────

    def _on_payload_select(self) -> None:
        row = self._payload_table.currentRow()
        if row < 0 or row >= len(self._payloads):
            return
        self._show_detail(self._payloads[row])

    def _show_detail(self, p: dict) -> None:
        layout = self._detail_content.layout()
        _clear_layout(layout)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # 타입 헤더
        type_lbl = QLabel(str(p.get("cape_type", "Unknown Payload")))
        type_lbl.setStyleSheet(f"color:{BLACK}; font-size:15px; font-weight:700;")
        type_lbl.setWordWrap(True)
        layout.addWidget(type_lbl)

        proc_lbl = QLabel(
            f"출처: {p.get('process_name', '—')}  (PID {p.get('pid', '—')})"
        )
        proc_lbl.setStyleSheet(f"color:{GRAY_500}; font-size:12px;")
        layout.addWidget(proc_lbl)

        # 해시 카드
        hash_items = [
            ("MD5",    str(p.get("md5", ""))),
            ("SHA1",   str(p.get("sha1", ""))),
            ("SHA256", str(p.get("sha256", ""))),
            ("SHA512", str(p.get("sha512", ""))),
            ("SSDeep", str(p.get("ssdeep", ""))),
            ("TLSH",   str(p.get("tlsh", ""))),
        ]
        layout.addWidget(HashCard("해시", hash_items))

        # 파일 정보 카드
        info_pairs = [
            ("크기",      f"{p.get('size', 0):,} bytes"),
            ("타입",      str(p.get("type", ""))[:80]),
            ("VA",        str(p.get("virtual_address", ""))),
            ("모듈 경로", str(p.get("module_path", ""))),
        ]
        info_card, ic_lay = _card_with_vbox(margins=(12, 12, 12, 12), spacing=6)
        for k, v in info_pairs:
            if not v or v == "0" or v == "0 bytes":
                continue
            row_lay = QHBoxLayout()
            k_lbl = QLabel(k.upper())
            k_lbl.setFixedWidth(80)
            k_lbl.setStyleSheet(_MONO_KEY_STYLE)
            v_lbl = QLabel(v)
            v_lbl.setStyleSheet(_MONO_VAL_STYLE)
            v_lbl.setWordWrap(True)
            row_lay.addWidget(k_lbl)
            row_lay.addWidget(v_lbl, 1)
            ic_lay.addLayout(row_lay)
        layout.addWidget(info_card)

        # YARA
        yara_names = [y.get("name", "") for y in (p.get("yara") or []) if isinstance(y, dict)]
        cape_yara_names = [y.get("name", "") for y in (p.get("cape_yara") or []) if isinstance(y, dict)]
        all_yara = yara_names + cape_yara_names
        if all_yara:
            y_lbl = QLabel(f"YARA 매치 ({len(all_yara)}개)")
            y_lbl.setStyleSheet(f"color:{BLACK}; font-size:13px; font-weight:600;")
            layout.addWidget(y_lbl)
            y_table = InfoTable(["Rule", "소스"])
            _fixed_height_table(y_table, len(all_yara))
            for name in yara_names:
                y_table.add_row([name, "YARA"])
            for name in cape_yara_names:
                y_table.add_row([name, "CAPE YARA"])
            y_table.fit_columns()
            layout.addWidget(y_table)

        layout.addStretch()


# --- MainWindow ---------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self, initial_path: str | None = None) -> None:
        super().__init__()
        self.setWindowTitle("CAPEv2 Report Analyzer")
        self.resize(1280, 800)
        self.setMinimumSize(900, 600)
        self.setAcceptDrops(True)

        self._build_toolbar()
        self._build_tabs()
        self._build_statusbar()

        if initial_path:
            self.load_report(initial_path)

    # -- 드래그 앤 드롭 --------------------------------------------------------

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            # .json 파일이 하나 이상 포함된 경우만 허용
            if any(u.toLocalFile().lower().endswith(".json") for u in urls):
                event.acceptProposedAction()
                return
        event.ignore()

    def dropEvent(self, event) -> None:
        urls = event.mimeData().urls()
        for url in urls:
            path = url.toLocalFile()
            if path.lower().endswith(".json"):
                self.load_report(path)
                break   # 첫 번째 JSON 파일만 처리

    # -- 레이아웃 빌더 ----------------------------------------------------------

    def _build_toolbar(self) -> None:
        bar = QToolBar()
        bar.setMovable(False)
        bar.setIconSize(QSize(0, 0))
        self.addToolBar(bar)

        open_btn = QPushButton("리포트 열기")
        open_btn.setObjectName("openBtn")
        open_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        open_btn.clicked.connect(self._open_file_dialog)
        bar.addWidget(open_btn)

        self._path_label = QLabel("파일을 선택하세요")
        self._path_label.setObjectName("pathLabel")
        self._path_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        bar.addWidget(self._path_label)

        self._score_badge = MalScoreBadge(0)
        self._score_badge_action = bar.addWidget(self._score_badge)
        self._score_badge_action.setVisible(False)

        self._ai_btn = QPushButton("AI 분석")
        self._ai_btn.setObjectName("aiBtn")
        self._ai_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._ai_btn.clicked.connect(self._open_analysis_dialog)
        self._ai_btn.setStyleSheet(
            "QPushButton#aiBtn {"
            "  background: #2563eb; color: #ffffff;"
            "  border-radius: 50px; padding: 6px 18px;"
            "  font-size: 13px; font-weight: 600; border: none;"
            "}"
            "QPushButton#aiBtn:hover { background: #1d4ed8; }"
        )
        self._ai_action = bar.addWidget(self._ai_btn)
        self._ai_action.setVisible(False)

    def _build_tabs(self) -> None:
        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)

        self._overview = OverviewTab()
        self._sigs     = SignaturesTab()
        self._attack   = ATTACKTab()
        self._network  = NetworkTab()
        self._behavior = BehaviorTab()
        self._cape     = CAPETab()

        self._tabs.addTab(self._overview, "Overview")
        self._tabs.addTab(self._sigs,    "Signatures")
        self._tabs.addTab(self._attack,  "ATT&CK")
        self._tabs.addTab(self._network, "Network")
        self._tabs.addTab(self._behavior,"Behavior")
        self._tabs.addTab(self._cape,    "CAPE")

        self.setCentralWidget(self._tabs)

    def _build_statusbar(self) -> None:
        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._status.showMessage("준비")

    # -- 파일 열기 --------------------------------------------------------------

    def _open_analysis_dialog(self) -> None:
        data = getattr(self, "_current_data", None)
        if data is None:
            return
        dlg = AnalysisDialog(data, parent=self)
        dlg.exec()

    def _open_file_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "CAPEv2 리포트 열기",
            os.path.expanduser("~"),
            "JSON 파일 (*.json);;모든 파일 (*)",
        )
        if path:
            self.load_report(path)

    _ASYNC_THRESHOLD = 50 * 1024 * 1024

    def load_report(self, path: str) -> None:
        self._status.showMessage(f"로딩 중: {path}")
        try:
            size = os.path.getsize(path)
        except OSError as e:
            self._status.showMessage(f"오류: {e}")
            return

        if size > self._ASYNC_THRESHOLD:
            self._start_async_load(path)
        else:
            try:
                data = ReportParser.load(path)
            except Exception as e:
                self._status.showMessage(f"오류: {e}")
                return
            self._apply_report(path, data)

    def _start_async_load(self, path: str) -> None:
        self._open_btn.setEnabled(False)
        self._status.showMessage(
            f"대용량 파일 로딩 중... {os.path.basename(path)}"
        )
        self._load_worker = _LoadWorker(path)
        self._load_worker.result_ready.connect(
            lambda data: self._apply_report(path, data)
        )
        self._load_worker.error.connect(self._on_load_error)
        self._load_worker.finished.connect(
            lambda: self._open_btn.setEnabled(True)
        )
        self._load_worker.start()

    def _on_load_error(self, msg: str) -> None:
        self._status.showMessage(f"오류: {msg}")
        self._open_btn.setEnabled(True)

    def _apply_report(self, path: str, data) -> None:
        self._path_label.setText(os.path.basename(path))
        self._path_label.setToolTip(path)
        self._score_badge.setScore(data.malscore)
        self._score_badge_action.setVisible(True)
        self._ai_action.setVisible(True)
        self._current_data = data

        self._overview.populate(data)
        self._sigs.populate(data)
        self._attack.populate(data)
        self._network.populate(data)
        self._behavior.populate(data)
        self._cape.populate(data)

        self._status.showMessage(
            f"로드 완료  |  ID {data.info.id}"
            f"  |  MalScore {data.malscore}"
            f"  |  Signatures {len(data.signatures)}개"
            f"  |  {data.malstatus}"
        )


# --- 유틸 --------------------------------------------------------------------

# 공통 스타일 상수 (f-string 중복 제거)
_MONO_KEY_STYLE = (
    f"color:{GRAY_500}; font-size:10px; letter-spacing:1px;"
    f" font-family:Consolas,monospace;"
)
_MONO_VAL_STYLE = f"color:{BLACK}; font-size:12px; font-family:Consolas,monospace;"
_SECTION_LBL_STYLE = (
    f"color:{GRAY_500}; font-size:11px; font-weight:600; margin-top:4px;"
)
_HEADER_BAR_STYLE = f"background:{WHITE}; border-bottom:1px solid {GRAY_200};"
_SPLITTER_STYLE = f"QSplitter::handle {{ background:{GRAY_200}; }}"


def _card_widget() -> QFrame:
    """흰 배경, 둥근 테두리 카드 컨테이너"""
    card = QFrame()
    card.setStyleSheet(
        f"QFrame {{ background:{WHITE}; border:1px solid {GRAY_200};"
        f" border-radius:8px; }}"
    )
    return card


def _clear_layout(layout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.deleteLater()
        else:
            sub = item.layout()
            if sub is not None:
                _clear_layout(sub)


def _card_with_vbox(margins=(16, 16, 16, 16), spacing: int = 10) -> tuple[QFrame, QVBoxLayout]:
    """_card_widget + 내부 QVBoxLayout을 한 번에 생성."""
    card = _card_widget()
    lay = QVBoxLayout(card)
    lay.setContentsMargins(*margins)
    lay.setSpacing(spacing)
    return card, lay


def _mono_kv_column(label: str, value: str, val_style: str | None = None) -> QVBoxLayout:
    """대문자 mono 레이블 + 값 2줄 컬럼."""
    col = QVBoxLayout()
    col.setSpacing(2)
    k = QLabel(label.upper())
    k.setStyleSheet(_MONO_KEY_STYLE)
    v = QLabel(value if value else "—")
    v.setStyleSheet(val_style or f"color:{BLACK}; font-size:13px; font-weight:500;")
    v.setWordWrap(True)
    col.addWidget(k)
    col.addWidget(v)
    return col


def _meta_row(pairs: list[tuple[str, str]], val_style: str | None = None) -> QHBoxLayout:
    """여러 (라벨,값) 컬럼을 한 줄로 배치."""
    row = QHBoxLayout()
    row.setSpacing(24)
    for label, val in pairs:
        row.addLayout(_mono_kv_column(label, val, val_style))
    row.addStretch()
    return row


def _kv_inline_row(label: str, value: str, key_width: int = 70) -> QHBoxLayout:
    """대문자 mono 라벨 + 값 1줄 (가로)."""
    row = QHBoxLayout()
    k = QLabel(label.upper())
    k.setFixedWidth(key_width)
    k.setStyleSheet(_MONO_KEY_STYLE)
    v = QLabel(value)
    v.setStyleSheet(f"color:{BLACK}; font-size:13px;")
    v.setWordWrap(True)
    row.addWidget(k)
    row.addWidget(v, 1)
    return row


def _section_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(_SECTION_LBL_STYLE)
    return lbl


def _header_bar(text: str) -> QWidget:
    """탭 상단의 회색 카운트 라벨이 달린 헤더 바."""
    bar = QWidget()
    bar.setStyleSheet(_HEADER_BAR_STYLE)
    lay = QHBoxLayout(bar)
    lay.setContentsMargins(16, 8, 16, 8)
    lbl = QLabel(text)
    lbl.setStyleSheet(f"color:{GRAY_500}; font-size:12px;")
    lay.addWidget(lbl)
    lay.addStretch()
    return bar


def _make_splitter() -> QSplitter:
    sp = QSplitter(Qt.Orientation.Horizontal)
    sp.setHandleWidth(1)
    sp.setStyleSheet(_SPLITTER_STYLE)
    return sp


def _fixed_height_table(table: InfoTable, n_rows: int, cap: int | None = None) -> None:
    rows = min(n_rows, cap) if cap else n_rows
    table.setMaximumHeight(28 + rows * 30)


# --- 진입점 ------------------------------------------------------------------

# --- AI 분석 -----------------------------------------------------------------

def _build_prompt(data: ReportData) -> str:
    """ReportData → Claude 프롬프트. UI 코드 없음, 순수 변환."""
    sig_lines  = [f"- [{s.severity}] {s.name}: {s.description}" for s in data.signatures[:20]]
    ttp_ids    = list(dict.fromkeys(t for ttp in data.ttps for t in ttp.ttps))[:15]
    cape_types = list(dict.fromkeys(
        str(p.get("cape_type", "")) for p in data.cape_payloads if p.get("cape_type")
    ))
    net_total  = sum(len(v) for v in data.suricata.values())

    # 네트워크 IOC 추출
    dns_domains = list(dict.fromkeys(
        str(e.get("request", "")) for e in data.suricata["dns"] if e.get("request")
    ))[:15]
    http_urls = list(dict.fromkeys(
        f"{e.get('dst', '')}:{e.get('dport', '')}{e.get('uri', '')}"
        for e in data.suricata["http"] if e.get("dst")
    ))[:10]
    tls_snis = list(dict.fromkeys(
        str(e.get("sni", "")) for e in data.suricata["tls"] if e.get("sni")
    ))[:10]
    alert_sigs = list(dict.fromkeys(
        str(e.get("signature", "")) for e in data.suricata["alerts"] if e.get("signature")
    ))[:10]

    net_section_parts = []
    if alert_sigs:
        net_section_parts.append("Suricata 알림:\n" + "\n".join(f"- {s}" for s in alert_sigs))
    if dns_domains:
        net_section_parts.append("DNS 요청 도메인:\n" + "\n".join(f"- {d}" for d in dns_domains))
    if http_urls:
        net_section_parts.append("HTTP 접속:\n" + "\n".join(f"- {u}" for u in http_urls))
    if tls_snis:
        net_section_parts.append("TLS SNI:\n" + "\n".join(f"- {s}" for s in tls_snis))
    net_section = "\n\n".join(net_section_parts) if net_section_parts else f"이벤트 {net_total}건 (세부 IOC 없음)"

    return f"""다음은 CAPEv2 악성코드 샌드박스 분석 결과입니다. 보안 전문가 관점에서 한국어로 분석해 주세요.

## 기본 정보
- MalScore: {data.malscore}/10  |  상태: {data.malstatus}
- 파일: {data.file_info.name}  |  크기: {data.file_info.size:,} bytes
- 타입: {data.file_info.file_type[:80]}
- CAPE 탐지: {', '.join(cape_types) if cape_types else '없음'}
- Suricata 이벤트: {net_total}건

## 탐지된 시그니처 ({len(data.signatures)}개)
{chr(10).join(sig_lines) if sig_lines else '없음'}

## MITRE ATT&CK TTP
{', '.join(ttp_ids) if ttp_ids else '없음'}


## 네트워크 활동
{net_section}
## 프로세스 행동
- 프로세스 수: {len(data.behavior_processes)}개
- 총 API 호출: {sum(len(p.calls) for p in data.behavior_processes):,}건

다음 항목을 포함해 분석해 주세요:
1. **악성코드 유형 및 목적** — 어떤 종류의 악성코드이며 무엇을 노리는지
2. **주요 행동 패턴** — 핵심 시그니처와 TTP 기반 설명
3. **공격 시나리오 흐름** — 실행 → 회피 → 목적 달성 순서로
4. **네트워크 IOC 평가** — C2 주소, 의심 도메인/URL 식별
5. **방어/대응 권고** — 구체적인 조치 2~3가지"""


class _AnalysisWorker(QThread):
    """AnalysisDialog 전용 백그라운드 스레드 — 외부 노출 안 함."""
    result_ready = pyqtSignal(str)
    error        = pyqtSignal(str)

    def __init__(self, prompt: str, api_key: str, provider: str) -> None:
        super().__init__()
        self._prompt   = prompt
        self._api_key  = api_key
        self._provider = provider  # "claude" | "gemini"
        self._cancelled  = False


    def cancel(self) -> None:
        self._cancelled = True
    def run(self) -> None:
        try:
            if self._provider == "claude":
                import anthropic
                client = anthropic.Anthropic(api_key=self._api_key)
                msg = client.messages.create(
                    model="claude-opus-4-6",
                    max_tokens=2000,
                    messages=[{"role": "user", "content": self._prompt}],
                )
                if not self._cancelled:
                    self.result_ready.emit(msg.content[0].text)
            else:  # gemini
                import google.generativeai as genai
                genai.configure(api_key=self._api_key)
                model = genai.GenerativeModel("gemini-2.5-flash")
                response = model.generate_content(self._prompt)
                if not self._cancelled:
                    self.result_ready.emit(response.text)
        except ImportError:
            pkg = "anthropic" if self._provider == "claude" else "google-generativeai"
            if not self._cancelled:
                self.error.emit(f"{pkg} 패키지가 없습니다.\n터미널에서: pip install {pkg}")
        except Exception as e:
            if not self._cancelled:
                self.error.emit(str(e))


class _LoadWorker(QThread):
    """50MB+ 대용량 리포트 비동기 로딩 전용 스레드."""
    result_ready = pyqtSignal(object)   # ReportData
    error        = pyqtSignal(str)

    def __init__(self, path: str) -> None:
        super().__init__()
        self._path = path

    def run(self) -> None:
        try:
            data = ReportParser.load(self._path)
            self.result_ready.emit(data)
        except Exception as e:
            self.error.emit(str(e))


class AnalysisDialog(QDialog):
    """Claude / Gemini API 분석 결과 다이얼로그."""

    # keyring 미사용 시 평문 파일 폴백 경로
    _KEY_PATHS = {
        "claude": os.path.expanduser("~/.cape_analyzer_claude_key"),
        "gemini": os.path.expanduser("~/.cape_analyzer_gemini_key"),
    }
    _KEYRING_SERVICE = "cape_analyzer"
    _PROVIDERS = [
        ("Claude (Anthropic)", "claude"),
        ("Gemini (Google)",    "gemini"),
    ]
    _PLACEHOLDERS = {
        "claude": "sk-ant-...",
        "gemini": "AIza...",
    }

    def __init__(self, data: ReportData, parent=None) -> None:
        super().__init__(parent)
        self._data    = data
        self._worker  = None
        self._api_key = ""
        self.setWindowTitle("AI 분석")
        self.resize(780, 620)
        self._setup_ui()
        self._load_key()

    # ── UI 구성 ───────────────────────────────────────────────────────────

    def _setup_ui(self) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 16, 20, 16)
        lay.setSpacing(12)

        # 제공자 선택
        provider_row = QHBoxLayout()
        provider_row.addWidget(QLabel("분석 모델:"))
        self._provider_combo = QComboBox()
        for label, value in self._PROVIDERS:
            self._provider_combo.addItem(label, value)
        self._provider_combo.setStyleSheet(
            f"border:1px solid {GRAY_200}; border-radius:6px; padding:4px 8px;"
        )
        self._provider_combo.currentIndexChanged.connect(self._on_provider_changed)
        provider_row.addWidget(self._provider_combo)
        provider_row.addStretch()
        lay.addLayout(provider_row)

        # API 키 입력 영역 (키 없을 때만 보임)
        self._key_frame = QFrame()
        self._key_frame.setStyleSheet(
            f"QFrame {{ background:{GRAY_50}; border:1px solid {GRAY_200}; border-radius:8px; }}"
        )
        kf_lay = QHBoxLayout(self._key_frame)
        kf_lay.setContentsMargins(12, 8, 12, 8)
        kf_lay.setSpacing(8)
        self._key_label = QLabel("API 키:")
        kf_lay.addWidget(self._key_label)
        self._key_input = QLineEdit()
        self._key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._key_input.setStyleSheet(
            f"border:1px solid {GRAY_200}; border-radius:6px; padding:4px 8px;"
        )
        kf_lay.addWidget(self._key_input, 1)
        save_btn = QPushButton("저장 후 분석")
        save_btn.setStyleSheet(
            f"background:{BLACK}; color:{WHITE}; border-radius:50px;"
            f" padding:4px 14px; font-weight:600; border:none;"
        )
        save_btn.clicked.connect(self._on_save_key)
        kf_lay.addWidget(save_btn)
        lay.addWidget(self._key_frame)

        # 상태 레이블
        self._status_lbl = QLabel("분석 준비 중...")
        self._status_lbl.setStyleSheet(f"color:{GRAY_500}; font-size:12px;")
        lay.addWidget(self._status_lbl)

        # 결과 텍스트 영역
        self._result_box = QTextEdit()
        self._result_box.setReadOnly(True)
        self._result_box.setStyleSheet(
            f"border:1px solid {GRAY_200}; border-radius:8px;"
            f" padding:12px; font-size:13px; background:{WHITE};"
        )
        lay.addWidget(self._result_box)

        # 하단 버튼
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        copy_btn = QPushButton("클립보드 복사")
        copy_btn.setStyleSheet(
            f"border:1px solid {GRAY_200}; border-radius:50px;"
            f" padding:4px 14px; background:{WHITE};"
        )
        copy_btn.clicked.connect(self._copy_result)
        btn_row.addWidget(copy_btn)

        save_btn = QPushButton("파일 저장")
        save_btn.setStyleSheet(
            f"border:1px solid {GRAY_200}; border-radius:50px;"
            f" padding:4px 14px; background:{WHITE};"
        )
        save_btn.clicked.connect(self._save_result)
        btn_row.addWidget(save_btn)

        retry_btn = QPushButton("다시 분석")
        retry_btn.setStyleSheet(
            f"border:1px solid {GRAY_200}; border-radius:50px;"
            f" padding:4px 14px; background:{WHITE};"
        )
        retry_btn.clicked.connect(self._start_analysis)
        btn_row.addWidget(retry_btn)
        close_btn = QPushButton("닫기")
        close_btn.setStyleSheet(
            f"background:{BLACK}; color:{WHITE}; border-radius:50px;"
            f" padding:4px 14px; font-weight:600; border:none;"
        )
        close_btn.clicked.connect(self.close)
        btn_row.addWidget(close_btn)
        lay.addLayout(btn_row)

    # ── 제공자 전환 ───────────────────────────────────────────────────────

    def _current_provider(self) -> str:
        return self._provider_combo.currentData()

    def _on_provider_changed(self) -> None:
        provider = self._current_provider()
        self._key_input.clear()
        self._key_input.setPlaceholderText(self._PLACEHOLDERS[provider])
        self._result_box.clear()
        self._api_key = ""
        self._load_key()

    # ── API 키 관리 ───────────────────────────────────────────────────────

    def _load_key(self) -> None:
        provider = self._current_provider()
        key = ""
        # 1순위: OS 키체인 (Windows Credential Manager / macOS Keychain)
        if _KEYRING_OK:
            try:
                stored = _keyring.get_password(self._KEYRING_SERVICE, provider)
                if stored:
                    key = stored
            except Exception:
                pass
        # 2순위: 평문 파일 폴백
        if not key:
            path = self._KEY_PATHS[provider]
            if os.path.exists(path):
                try:
                    with open(path, encoding="utf-8") as f:
                        key = f.read().strip()
                except OSError:
                    pass
        if key:
            self._api_key = key
            self._key_frame.setVisible(False)
            self._start_analysis()
            return
        self._key_input.setPlaceholderText(self._PLACEHOLDERS[provider])
        self._key_frame.setVisible(True)
        self._status_lbl.setText("API 키를 입력하세요. 저장되면 다음부터 자동으로 사용합니다.")

    def _on_save_key(self) -> None:
        provider = self._current_provider()
        key = self._key_input.text().strip()
        if not key:
            self._status_lbl.setText("API 키를 입력하세요.")
            return
        if provider == "claude" and not key.startswith("sk-ant-"):
            self._status_lbl.setText("올바른 Anthropic API 키를 입력하세요 (sk-ant-... 형식).")
            return
        # 1순위: OS 키체인에 저장 — 평문 파일보다 안전
        if _KEYRING_OK:
            try:
                _keyring.set_password(self._KEYRING_SERVICE, provider, key)
                self._api_key = key
                self._key_frame.setVisible(False)
                self._start_analysis()
                return
            except Exception as e:
                self._status_lbl.setText(f"키체인 저장 실패, 파일로 폴백: {e}")
        # 2순위: 평문 파일 저장
        try:
            path = self._KEY_PATHS[provider]
            with open(path, "w", encoding="utf-8") as f:
                f.write(key)
            # 소유자만 읽기/쓰기 가능하도록 권한 설정 (Unix 계열)
            try:
                import stat
                os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            except (OSError, AttributeError):
                pass  # Windows에서는 무시
        except OSError as e:
            self._status_lbl.setText(f"키 저장 실패: {e}")
            return
        self._api_key = key
        self._key_frame.setVisible(False)
        self._start_analysis()

    # ── 분석 실행 ─────────────────────────────────────────────────────────

    def _start_analysis(self) -> None:
        if not self._api_key:
            self._key_frame.setVisible(True)
            return
        if self._worker and self._worker.isRunning():
            return
        provider = self._current_provider()
        provider_name = self._provider_combo.currentText()
        self._result_box.clear()
        self._status_lbl.setText(f"분석 중... ({provider_name} API 호출)")
        prompt = _build_prompt(self._data)
        self._worker = _AnalysisWorker(prompt, self._api_key, provider)
        self._worker.result_ready.connect(self._on_result)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_result(self, text: str) -> None:
        self._result_box.setMarkdown(text)
        self._status_lbl.setText("분석 완료.")

    def _on_error(self, msg: str) -> None:
        self._result_box.setPlainText(f"오류 발생:\n{msg}")
        self._status_lbl.setText("오류가 발생했습니다.")

    def _copy_result(self) -> None:
        text = self._result_box.toPlainText().strip()
        if not text:
            self._status_lbl.setText("복사할 내용이 없습니다.")
            return
        QGuiApplication.clipboard().setText(text)
        self._status_lbl.setText("클립보드에 복사했습니다.")

    def _save_result(self) -> None:
        text = self._result_box.toPlainText().strip()
        if not text:
            self._status_lbl.setText("저장할 내용이 없습니다.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "분석 결과 저장", "ai_analysis.txt",
            "텍스트 파일 (*.txt);;Markdown 파일 (*.md);;모든 파일 (*)",
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            self._status_lbl.setText(f"저장 완료: {path}")
        except OSError as e:
            self._status_lbl.setText(f"저장 실패: {e}")

    def closeEvent(self, event) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self._worker.quit()
            if not self._worker.wait(3000):  # 3초 내 자연 종료 대기
                self._worker.terminate()     # 최후 수단
                self._worker.wait()
        super().closeEvent(event)


def main() -> None:
    app = QApplication(sys.argv)
    app.setStyleSheet(APP_STYLE)

    initial_path = sys.argv[1] if len(sys.argv) > 1 else None
    win = MainWindow(initial_path)
    win.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
