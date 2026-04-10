# CAPEv2 Report Analyzer

CAPEv2 악성코드 샌드박스가 생성한 `{id}_report.json` 파일을 읽어 분석 결과를 시각화하는 PyQt6 데스크탑 앱.

![Python](https://img.shields.io/badge/Python-3.11+-blue) ![PyQt6](https://img.shields.io/badge/PyQt6-6.x-green)

---

## 주요 기능

- **Overview** — 파일 해시(클릭 시 클립보드 복사), PE 정보, YARA 매치, VirusTotal 탐지율, 위협 요약 카드
- **Signatures** — 심각도 필터 + 시그니처별 증거 상세 패널
- **ATT&CK** — MITRE ATT&CK TTP 테이블 (클릭 시 MITRE 링크 오픈)
- **Network** — Suricata Alerts / DNS / HTTP / TLS / SSH / Files 서브탭
- **Behavior** — 프로세스 목록 + API 호출 테이블
- **CAPE** — 추출 페이로드 해시 및 악성코드 설정값
- **AI 분석** — Claude / Gemini API를 이용한 한국어 분석 리포트 생성

---

## 설치 및 실행

```bash
pip install PyQt6
python main.py

# 파일을 인자로 직접 전달
python main.py path/to/13_report.json
```

JSON 파일을 창에 드래그 앤 드롭해도 열립니다.

---

## AI 분석 기능

툴바의 **AI 분석** 버튼 클릭 후 API 키를 입력하면 자동 저장되며, 이후 분석 시 재입력 없이 사용 가능합니다.

| 제공자 | 패키지 |
|--------|--------|
| Claude (Anthropic) | `pip install anthropic` |
| Gemini (Google) | `pip install google-generativeai` |

---

## 파일 구조

```
ReportAnalysis/
├── main.py      # 앱 진입점 + MainWindow + 탭 클래스 6개
├── parser.py    # ReportParser + 데이터클래스
└── widgets.py   # 공통 UI 컴포넌트
```
