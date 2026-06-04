# 11. 대시보드 UI/UX 프리뷰 설계

## 1. 목적

기존 `/__waf/dashboard` 화면을 직접 바꾸기 전에, 완성 UI/UX 개선안을 실제 서버 라우트에서 100% 동일한 HTML/CSS 렌더링으로 미리 확인한다.

## 2. 프리뷰 라우트

| 번호 | 항목 | 내용 |
|---|---|---|
| 2-1 | URL | `/__waf/dashboard-preview` |
| 2-2 | 인증 | 기존 대시보드 로그인 세션 필요 |
| 2-3 | 영향 범위 | 기존 `/__waf/dashboard`는 변경하지 않음 |
| 2-4 | 렌더링 방식 | 기존 `dashboard/layout.html` + preview 전용 partial + 같은 CSS/JS |

## 3. UI 개선 방향

| 번호 | 문제 | 개선 |
|---|---|---|
| 3-1 | AI 카드 중복 | 하나는 AI Second Pass 상태 카드로 정리 |
| 3-2 | `No threats`와 전체 차단 수 모순 | 최근 차단과 전체 차단을 분리 표시 |
| 3-3 | Security Score 근거 부족 | 총 로그, 차단 수, 차단율을 같이 표시 |
| 3-4 | 긴 공격명 가독성 낮음 | Top 3 리스트 중심으로 단순화 |
| 3-5 | 하단 상태 문구가 개발자용 | 운영자 친화 문구로 변경 |
| 3-6 | 다음 행동이 약함 | 탐지 상세, 프록시 로그, 설정 이동 버튼 추가 |

## 4. 예상 구현 파일

| 번호 | 파일 | 역할 |
|---|---|---|
| 4-1 | `dashboard_app.py` | preview 라우트 등록 |
| 4-2 | `templates/dashboard/partials/overview_preview.html` | preview 화면 구조 |
| 4-3 | `static/waf/css/dashboard.css` | preview 전용 스타일 |
| 4-4 | `verification/waf_dashboard.py` | preview 라우트 테스트 |

## 5. 완료 기준

- [ ] `/__waf/dashboard-preview`가 200으로 렌더링된다.
- [ ] 기존 `/__waf/dashboard` 테스트가 깨지지 않는다.
- [ ] preview 화면에 중복 AI 카드가 없다.
- [ ] 최근 차단과 전체 차단이 분리되어 보인다.
- [ ] 주요 행동 버튼이 보인다.
