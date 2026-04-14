from __future__ import annotations
from PyQt6.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QHBoxLayout,
    QGroupBox, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QSizePolicy, QFrame,
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont, QColor, QClipboard, QGuiApplication


# Design tokens — Soft palette (#F6F4E8 · #E5EEE4 · #C0E1D2 · #DC9B9B)

CREAM    = "#F6F4E8"   # 메인 배경 (따뜻한 크림)
SAGE     = "#E5EEE4"   # 보조 배경 · 교번행 · 패널
MINT     = "#C0E1D2"   # 액센트 · 선택 상태 · 탭 인디케이터
ROSE     = "#DC9B9B"   # 위험 · 높은 심각도

# 하위 호환 별칭 (main.py import 유지)
BLACK    = "#2C3830"   # 기본 텍스트 (소프트 다크 그린-블랙)
WHITE    = CREAM       # 메인 배경
GRAY_50  = SAGE        # 교번행 배경
GRAY_200 = "#D4E0D2"   # 테두리
GRAY_500 = "#6B8A7A"   # 보조 텍스트 (그린-그레이)

# 심각도 색
SEVERITY_COLORS = {
    1: (SAGE,      "#3D6B5A"),   # Info     — sage bg, 다크 틸 text
    2: ("#F0ECD8", "#7A5C3A"),   # Low      — 따뜻한 크림 bg, 브라운 text
    3: ("#F5E4D5", "#8C4A30"),   # Medium   — 소프트 오렌지 bg
    4: ("#F0D8D8", "#8C2020"),   # High     — 로즈-크림 bg
    5: (ROSE,      "#2C1A1A"),   # Critical — ROSE bg, 다크 text
}
SEVERITY_LABELS = {1: "Info", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}

# MalScore 색
def malscore_color(score: int) -> tuple[str, str]:
    """(bg, text) 반환"""
    if score <= 3:
        return (SAGE, "#3D6B5A")        # 세이지-틸
    if score <= 6:
        return ("#F5E4D5", "#8C4A30")   # 소프트 오렌지
    return ("#F0D8D8", "#8C2020")       # 로즈-레드


# 공통 스타일 헬퍼

def _pill_style(bg: str, fg: str, font_size: int = 12, bold: bool = False) -> str:
    weight = "600" if bold else "400"
    return (
        f"background:{bg}; color:{fg}; border-radius:50px;"
        f" padding:3px 10px; font-size:{font_size}px; font-weight:{weight};"
        f" border:none;"
    )

def _mono_label(text: str, color: str = GRAY_500) -> QLabel:
    """figmaMono 스타일 — 대문자 섹션 레이블"""
    lbl = QLabel(text.upper())
    lbl.setStyleSheet(
        f"color:{color}; font-size:11px; letter-spacing:1px; font-weight:400;"
    )
    lbl.setFont(QFont("Consolas", 9))
    return lbl


# 1. SeverityBadge

class SeverityBadge(QLabel):
    """심각도 1–5 에 맞는 색상 필 배지"""

    def __init__(self, severity: int, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        severity = max(1, min(5, severity))
        bg, fg = SEVERITY_COLORS.get(severity, (WHITE, BLACK))
        label = SEVERITY_LABELS.get(severity, str(severity))
        self.setText(label)
        self.setStyleSheet(_pill_style(bg, fg, font_size=11, bold=True))
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFixedWidth(70)


# 2. MalScoreBadge

class MalScoreBadge(QLabel):
    """MalScore 0–10 색상 배지 (툴바용 — 넓은 필)"""

    def __init__(self, score: int = 0, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setScore(score)

    def setScore(self, score: int) -> None:
        bg, fg = malscore_color(score)
        self.setText(f"MalScore  {score} / 10")
        self.setStyleSheet(_pill_style(bg, fg, font_size=13, bold=True))
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFixedSize(QSize(160, 30))


# 3. HashCard

class HashCard(QGroupBox):
    """
    해시 키-값 목록을 표시하고, 값 클릭 시 클립보드 복사.
    items: [(label, value), ...]
    """

    def __init__(
        self,
        title: str,
        items: list[tuple[str, str]],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setTitle("")
        self.setStyleSheet(
            f"QGroupBox {{ background:{WHITE}; border:1px solid {GRAY_200};"
            f" border-radius:8px; padding:12px; }}"
        )

        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        layout.setContentsMargins(12, 12, 12, 12)

        if title:
            hdr = QLabel(title)
            hdr.setStyleSheet(
                f"color:{BLACK}; font-size:13px; font-weight:600;"
                f" border:none; background:transparent;"
            )
            layout.addWidget(hdr)

        for label, value in items:
            row = QHBoxLayout()
            row.setSpacing(8)

            key_lbl = _mono_label(label)
            key_lbl.setFixedWidth(90)
            key_lbl.setStyleSheet(
                key_lbl.styleSheet() + " border:none; background:transparent;"
            )
            row.addWidget(key_lbl)

            val_btn = QPushButton(value if value else "—")
            val_btn.setFlat(True)
            val_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            val_btn.setStyleSheet(
                f"QPushButton {{"
                f"  color:{BLACK}; background:transparent; border:none;"
                f"  font-family:Consolas,monospace; font-size:12px;"
                f"  text-align:left; padding:0;"
                f"}}"
                f"QPushButton:hover {{ color:#3D6B5A; }}"
            )
            if value:
                val_btn.clicked.connect(lambda _, v=value: self._copy(v))
                val_btn.setToolTip("클릭하여 클립보드에 복사")
            row.addWidget(val_btn, 1)
            layout.addLayout(row)

    @staticmethod
    def _copy(text: str) -> None:
        QGuiApplication.clipboard().setText(text)


# 4. InfoTable

class InfoTable(QTableWidget):
    """
    기본 스타일이 적용된 읽기 전용 테이블.
    columns: [str, ...]
    """

    def __init__(
        self,
        columns: list[str],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(0, len(columns), parent)
        self.setHorizontalHeaderLabels(columns)
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setAlternatingRowColors(True)
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setStretchLastSection(True)
        self.setShowGrid(False)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self.setStyleSheet(
            f"""
            QTableWidget {{
                background: {WHITE};
                alternate-background-color: {GRAY_50};
                border: 1px solid {GRAY_200};
                border-radius: 8px;
                font-size: 13px;
                color: {BLACK};
                outline: none;
            }}
            QTableWidget::item {{
                padding: 6px 10px;
                border: none;
            }}
            QTableWidget::item:selected {{
                background: {MINT};
                color: {BLACK};
            }}
            QHeaderView::section {{
                background: {WHITE};
                color: {GRAY_500};
                font-size: 11px;
                font-weight: 600;
                letter-spacing: 0.5px;
                padding: 6px 10px;
                border: none;
                border-bottom: 1px solid {GRAY_200};
            }}
            """
        )

    def add_row(self, values: list[str]) -> int:
        """행 추가 후 행 인덱스 반환"""
        row = self.rowCount()
        self.insertRow(row)
        for col, val in enumerate(values):
            item = QTableWidgetItem(str(val) if val is not None else "")
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.setItem(row, col, item)
        return row

    def set_widget_in_cell(self, row: int, col: int, widget: QWidget) -> None:
        """셀에 위젯 삽입 (배지 등)"""
        container = QWidget()
        lay = QHBoxLayout(container)
        lay.setContentsMargins(6, 2, 6, 2)
        lay.addWidget(widget)
        lay.addStretch()
        self.setCellWidget(row, col, container)

    def fit_columns(self) -> None:
        """내용에 맞게 열 너비 조정 (마지막 열 제외)"""
        for col in range(self.columnCount() - 1):
            self.resizeColumnToContents(col)


# 5. EmptyState

class EmptyState(QWidget):
    """데이터가 없을 때 표시하는 안내 위젯"""

    def __init__(
        self,
        message: str = "데이터 없음",
        sub: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(8)

        icon = QLabel("○")
        icon.setStyleSheet(f"color:{GRAY_200}; font-size:40px;")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon)

        msg = QLabel(message)
        msg.setStyleSheet(
            f"color:{GRAY_500}; font-size:14px; font-weight:500;"
        )
        msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(msg)

        if sub:
            sub_lbl = QLabel(sub)
            sub_lbl.setStyleSheet(f"color:{GRAY_200}; font-size:12px;")
            sub_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(sub_lbl)
