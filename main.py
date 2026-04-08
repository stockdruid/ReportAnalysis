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

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget,
    QVBoxLayout, QHBoxLayout, QToolBar, QPushButton,
    QLabel, QFileDialog, QStatusBar, QSizePolicy,
    QScrollArea, QFrame, QSplitter, QHeaderView,
)
from PyQt6.QtCore import Qt, QSize

from parser import ReportParser, ReportData
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

        # ── 1. 파일 요약 카드 ──────────────────────────────────────────────
        summary_card = _card_widget()
        s_lay = QVBoxLayout(summary_card)
        s_lay.setContentsMargins(16, 16, 16, 16)
        s_lay.setSpacing(10)

        title = QLabel(fi.name if fi.name else "Unknown")
        title.setStyleSheet(f"color:{BLACK}; font-size:18px; font-weight:700;")
        s_lay.addWidget(title)

        meta_row = QHBoxLayout()
        meta_row.setSpacing(24)
        for label, val in [
            ("크기", f"{fi.size:,} bytes"),
            ("타입", fi.file_type[:60] if fi.file_type else "—"),
            ("패키지", data.info.package),
            ("분석 머신", data.info.machine),
            ("소요 시간", f"{data.info.duration}초"),
        ]:
            col = QVBoxLayout()
            col.setSpacing(2)
            k = QLabel(label.upper())
            k.setStyleSheet(
                f"color:{GRAY_500}; font-size:10px; letter-spacing:1px;"
                f" font-family:Consolas,monospace;"
            )
            v = QLabel(val)
            v.setStyleSheet(f"color:{BLACK}; font-size:13px; font-weight:500;")
            v.setWordWrap(True)
            col.addWidget(k)
            col.addWidget(v)
            meta_row.addLayout(col)
        meta_row.addStretch()
        s_lay.addLayout(meta_row)

        # 분석 시간
        time_row = QHBoxLayout()
        time_row.setSpacing(24)
        for label, val in [
            ("시작", data.info.started),
            ("종료", data.info.ended),
            ("상태", data.malstatus),
            ("CAPE 탐지", fi.cape_type if fi.cape_type else "—"),
        ]:
            col = QVBoxLayout()
            col.setSpacing(2)
            k = QLabel(label.upper())
            k.setStyleSheet(
                f"color:{GRAY_500}; font-size:10px; letter-spacing:1px;"
                f" font-family:Consolas,monospace;"
            )
            v = QLabel(val)
            v.setStyleSheet(f"color:{BLACK}; font-size:13px;")
            col.addWidget(k)
            col.addWidget(v)
            time_row.addLayout(col)
        time_row.addStretch()
        s_lay.addLayout(time_row)

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
        pe_card = _card_widget()
        pe_lay = QVBoxLayout(pe_card)
        pe_lay.setContentsMargins(16, 16, 16, 16)
        pe_lay.setSpacing(12)

        pe_title = QLabel("PE 정보")
        pe_title.setStyleSheet(f"color:{BLACK}; font-size:14px; font-weight:700;")
        pe_lay.addWidget(pe_title)

        # PE 기본 메타
        pe_meta = QHBoxLayout()
        pe_meta.setSpacing(24)
        for label, val in [
            ("Timestamp",   fi.pe_timestamp),
            ("ImageBase",   fi.pe_imagebase),
            ("EntryPoint",  fi.pe_entrypoint),
            ("OS Version",  fi.pe_osversion),
            ("Machine",     fi.pe_machine_type),
        ]:
            col = QVBoxLayout()
            col.setSpacing(2)
            k = QLabel(label.upper())
            k.setStyleSheet(
                f"color:{GRAY_500}; font-size:10px; letter-spacing:1px;"
                f" font-family:Consolas,monospace;"
            )
            v = QLabel(val if val else "—")
            v.setStyleSheet(f"color:{BLACK}; font-size:12px; font-family:Consolas,monospace;")
            col.addWidget(k)
            col.addWidget(v)
            pe_meta.addLayout(col)
        pe_meta.addStretch()
        pe_lay.addLayout(pe_meta)

        if fi.pe_pdbpath:
            pdb_row = QHBoxLayout()
            pdb_lbl = QLabel("PDB")
            pdb_lbl.setStyleSheet(
                f"color:{GRAY_500}; font-size:10px; letter-spacing:1px;"
                f" font-family:Consolas,monospace; min-width:60px;"
            )
            pdb_val = QLabel(fi.pe_pdbpath)
            pdb_val.setStyleSheet(
                f"color:{BLACK}; font-size:12px; font-family:Consolas,monospace;"
            )
            pdb_val.setWordWrap(True)
            pdb_row.addWidget(pdb_lbl)
            pdb_row.addWidget(pdb_val, 1)
            pe_lay.addLayout(pdb_row)

        # 섹션 테이블
        if fi.pe_sections:
            sec_lbl = QLabel("섹션")
            sec_lbl.setStyleSheet(
                f"color:{GRAY_500}; font-size:11px; font-weight:600; margin-top:4px;"
            )
            pe_lay.addWidget(sec_lbl)

            sec_table = InfoTable(["이름", "VA", "크기", "특성", "엔트로피"])
            sec_table.setMaximumHeight(28 + len(fi.pe_sections) * 30)
            for sec in fi.pe_sections:
                sec_table.add_row([
                    sec.name,
                    sec.virtual_address,
                    sec.size_of_data,
                    sec.characteristics,
                    f"{sec.entropy:.2f}",
                ])
            sec_table.fit_columns()
            pe_lay.addWidget(sec_table)

        # VersionInfo
        if fi.pe_versioninfo:
            ver_lbl = QLabel("Version Info")
            ver_lbl.setStyleSheet(
                f"color:{GRAY_500}; font-size:11px; font-weight:600; margin-top:4px;"
            )
            pe_lay.addWidget(ver_lbl)
            ver_table = InfoTable(["Key", "Value"])
            ver_table.setMaximumHeight(28 + len(fi.pe_versioninfo) * 30)
            for entry in fi.pe_versioninfo:
                ver_table.add_row([
                    str(entry.get("name", "")),
                    str(entry.get("value", "")),
                ])
            ver_table.fit_columns()
            pe_lay.addWidget(ver_table)

        # Imports
        if fi.pe_imports:
            imp_lbl = QLabel(f"임포트 DLL ({len(fi.pe_imports)}개)")
            imp_lbl.setStyleSheet(
                f"color:{GRAY_500}; font-size:11px; font-weight:600; margin-top:4px;"
            )
            pe_lay.addWidget(imp_lbl)
            imp_table = InfoTable(["DLL", "함수 수"])
            imp_table.setMaximumHeight(28 + min(len(fi.pe_imports), 10) * 30)
            for imp in fi.pe_imports:
                dll = str(imp.get("dll", ""))
                funcs = imp.get("imports", [])
                imp_table.add_row([dll, str(len(funcs))])
            imp_table.fit_columns()
            pe_lay.addWidget(imp_table)

        # Digital Signers
        if fi.pe_digital_signers:
            sig_lbl = QLabel("디지털 서명")
            sig_lbl.setStyleSheet(
                f"color:{GRAY_500}; font-size:11px; font-weight:600; margin-top:4px;"
            )
            pe_lay.addWidget(sig_lbl)
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
            yara_card = _card_widget()
            y_lay = QVBoxLayout(yara_card)
            y_lay.setContentsMargins(16, 16, 16, 16)
            y_lay.setSpacing(8)
            y_title = QLabel(f"YARA 매치 ({len(all_yara)}개)")
            y_title.setStyleSheet(f"color:{BLACK}; font-size:14px; font-weight:700;")
            y_lay.addWidget(y_title)

            yara_table = InfoTable(["Rule", "소스"])
            yara_table.setMaximumHeight(28 + len(all_yara) * 30)
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
            vt_card = _card_widget()
            vt_lay = QVBoxLayout(vt_card)
            vt_lay.setContentsMargins(16, 16, 16, 16)
            vt_lay.setSpacing(8)
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
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(1)
        splitter.setStyleSheet(f"QSplitter::handle {{ background:{GRAY_200}; }}")

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
            row = QHBoxLayout()
            k_lbl = QLabel(k.upper())
            k_lbl.setFixedWidth(70)
            k_lbl.setStyleSheet(
                f"color:{GRAY_500}; font-size:10px; letter-spacing:1px;"
                f" font-family:Consolas,monospace;"
            )
            v_lbl = QLabel(v)
            v_lbl.setStyleSheet(f"color:{BLACK}; font-size:13px;")
            v_lbl.setWordWrap(True)
            row.addWidget(k_lbl)
            row.addWidget(v_lbl, 1)
            layout.addLayout(row)

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
                ev_card = _card_widget()
                ev_lay = QVBoxLayout(ev_card)
                ev_lay.setContentsMargins(10, 8, 10, 8)
                ev_lay.setSpacing(4)
                for ek, ev in (entry.items() if isinstance(entry, dict) else [("값", entry)]):
                    ev_row = QHBoxLayout()
                    ek_lbl = QLabel(str(ek).upper())
                    ek_lbl.setFixedWidth(80)
                    ek_lbl.setStyleSheet(
                        f"color:{GRAY_500}; font-size:10px; letter-spacing:1px;"
                        f" font-family:Consolas,monospace;"
                    )
                    ev_val = QLabel(self._fmt_evidence(ev))
                    ev_val.setStyleSheet(
                        f"color:{BLACK}; font-size:12px; font-family:Consolas,monospace;"
                    )
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
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(20, 20, 20, 20)
        self._layout.addWidget(EmptyState("리포트를 열어주세요"))

    def populate(self, data: ReportData) -> None:
        # Step 6 에서 구현
        _clear_layout(self._layout)
        self._layout.addWidget(QLabel(
            f"ATT&CK — TTP {len(data.ttps)}개 (Step 6 에서 구현)"
        ))


class NetworkTab(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(20, 20, 20, 20)
        self._layout.addWidget(EmptyState("리포트를 열어주세요"))

    def populate(self, data: ReportData) -> None:
        # Step 7 에서 구현
        _clear_layout(self._layout)
        total = sum(len(v) for v in data.suricata.values())
        self._layout.addWidget(QLabel(
            f"Network — Suricata 이벤트 {total}개 (Step 7 에서 구현)"
        ))


class BehaviorTab(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(20, 20, 20, 20)
        self._layout.addWidget(EmptyState("리포트를 열어주세요"))

    def populate(self, data: ReportData) -> None:
        # Step 8 에서 구현
        _clear_layout(self._layout)
        total_calls = sum(len(p.calls) for p in data.behavior_processes)
        self._layout.addWidget(QLabel(
            f"Behavior — 프로세스 {len(data.behavior_processes)}개 / "
            f"API 호출 {total_calls}개 (Step 8 에서 구현)"
        ))


class CAPETab(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(20, 20, 20, 20)
        self._layout.addWidget(EmptyState("리포트를 열어주세요"))

    def populate(self, data: ReportData) -> None:
        # Step 9 에서 구현
        _clear_layout(self._layout)
        self._layout.addWidget(QLabel(
            f"CAPE — 페이로드 {len(data.cape_payloads)}개 / "
            f"설정 {len(data.cape_configs)}개 (Step 9 에서 구현)"
        ))


# --- MainWindow ---------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self, initial_path: str | None = None) -> None:
        super().__init__()
        self.setWindowTitle("CAPEv2 Report Analyzer")
        self.resize(1280, 800)
        self.setMinimumSize(900, 600)

        self._build_toolbar()
        self._build_tabs()
        self._build_statusbar()

        if initial_path:
            self.load_report(initial_path)

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
        self._score_badge.setVisible(False)
        bar.addWidget(self._score_badge)

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

    def _open_file_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "CAPEv2 리포트 열기",
            os.path.expanduser("~"),
            "JSON 파일 (*.json);;모든 파일 (*)",
        )
        if path:
            self.load_report(path)

    def load_report(self, path: str) -> None:
        self._status.showMessage(f"로딩 중: {path}")
        try:
            data = ReportParser.load(path)
        except Exception as e:
            self._status.showMessage(f"오류: {e}")
            return

        self._path_label.setText(os.path.basename(path))
        self._path_label.setToolTip(path)
        self._score_badge.setScore(data.malscore)
        self._score_badge.setVisible(True)

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

def _card_widget() -> QFrame:
    """흰 배경, 둥근 테두리 카드 컨테이너"""
    card = QFrame()
    card.setStyleSheet(
        f"QFrame {{ background:{WHITE}; border:1px solid {GRAY_200};"
        f" border-radius:8px; }}"
    )
    return card


def _clear_layout(layout: QVBoxLayout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        if item.widget():
            item.widget().deleteLater()


# --- 진입점 ------------------------------------------------------------------

def main() -> None:
    app = QApplication(sys.argv)
    app.setStyleSheet(APP_STYLE)

    initial_path = sys.argv[1] if len(sys.argv) > 1 else None
    win = MainWindow(initial_path)
    win.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
