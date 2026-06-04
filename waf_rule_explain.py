"""403 차단 페이지·API용 규칙별 설명 텍스트 (rule_id + evidence 파싱)."""

from __future__ import annotations

# owasp/a10.py 의 _Rule 설명과 동기화 (요약 한 줄)
_A10_EXACT: dict[str, str] = {
    "A10-UNDEF-001": "'undefined'를 리소스 ID로 사용 — Node.js TypeError 유발 (CWE-391)",
    "A10-UNDEF-002": "'NaN' 또는 'Infinity'를 리소스 ID로 사용 — 수치 강제 변환 실패 (CWE-390)",
    "A10-UNDEF-003": "'null'을 리소스 ID로 사용 — Null 포인터 참조 예외 (CWE-476)",
    "A10-PROTO-001": "__proto__ 키 주입 — JavaScript 프로토타입 오염 (CWE-1321)",
    "A10-PROTO-002": "constructor.prototype 체인 조작 — JS/JSON 프로토타입 오염 (CWE-1321)",
    "A10-PROTO-003": "__defineGetter__/__defineSetter__ — 레거시 프로토타입 재정의 (CWE-1321)",
    "A10-BOUND-001": "JS MAX_SAFE_INTEGER 초과 ID — 정수 정밀도 손실·ORM 오류 (CWE-190)",
    "A10-BOUND-002": "음수 정수 리소스 ID — ORM '행 없음' 예외 미처리 (CWE-391)",
    "A10-BOUND-003": "INT32 경계값(±2147483647/2147483648) — 부호 오버플로 (CWE-190)",
    "A10-BOUND-004": "0을 리소스 ID로 사용 — ORM 결과 없음 미처리 예외 (CWE-391)",
    "A10-NULLB-001": "URL 인코딩된 null 바이트(%00) — 검증 우회·경계 위반 (CWE-626)",
    "A10-NULLB-002": "본문 내 리터럴 null 바이트 — 파서 크래시·문자열 경계 위반 (CWE-626)",
    "A10-NULLB-003": "Overlong UTF-8 null 인코딩(%c0%80) — 유니코드 우회 (CWE-116)",
    "A10-FMT-001": "Printf 형식 지정자 연속 — C/C++ 메모리 누출·크래시 (CWE-134)",
    "A10-FMT-002": "Node.js util.format 지정자 연속 — 민감 정보 로그 인젝션 (CWE-117)",
    "A10-TYPECONF-001": "NoSQL 연산자를 스칼라 필드 값으로 주입 — ORM 타입 불일치 (CWE-843)",
    "A10-TYPECONF-002": "인증 필드에 오브젝트 주입 — 로그인 핸들러 타입 변환 예외 (CWE-843)",
    "A10-TYPECONF-003": "JSON 루트가 배열 — 단일 오브젝트 기대 엔드포인트 타입 혼동 (CWE-843)",
    "A10-ERRPRB-001": "검색 쿼리 괄호 불균형 — SQLite FTS5 파서 오류·미처리 예외 (CWE-391)",
    "A10-ERRPRB-002": "ORM 오류 생성 함수 주입(extractvalue/updatexml 등) — DB 오류 정보 노출 (CWE-209)",
    "A10-ERRPRB-003": "백업/디버그 파일 확장자 접근 — 소스·설정 노출 (CWE-209)",
    "A10-DEEP-001": "JSON 중첩 깊이 과다 — 스택 오버플로·DoS (CWE-400)",
    "A10-HDRNOM-001": "역순 Range 헤더(end < start) — 비정상 요청·버그 유발",
    "A10-HDRNOM-002": "비정상적으로 큰 단일 헤더 값 — 버퍼·파서 한계 초과",
}


def rule_explain(rule_id: str, evidence: str) -> str:
    """탐지 규칙에 대한 한국어 설명 (고정 맵 + 모듈별 evidence 형식 파싱)."""
    ev = (evidence or "").strip()
    rid = (rule_id or "").strip().upper()

    # A05: evidence = "설명 | 탐지값: '...'"
    if " | 탐지값:" in ev:
        return ev.split(" | 탐지값:", 1)[0].strip()

    # A06: evidence = "[A06 불안전한 설계] 요약 | 세부"
    if ev.startswith("[A06 불안전한 설계]"):
        body = ev[len("[A06 불안전한 설계] ") :].strip()
        if " | " in body:
            return body.split(" | ", 1)[0].strip()
        return body[:500]

    if rid in _A10_EXACT:
        return _A10_EXACT[rid]

    if rid.startswith("A10-"):
        return (
            "A10:2025 예외·비정상 조건 — 요청이 비정상 입력·헤더·본문 패턴과 일치합니다. "
            "스택/DB 오류 노출·크래시 등으로 이어질 수 있습니다."
        )
    if rid.startswith("A06-"):
        return (
            "A06:2025 안전하지 않은 설계 — 비즈니스 로직·가격·권한·경로 등 "
            "설계 단계에서 막아야 할 패턴이 요청에 포함되었습니다."
        )
    if rid.startswith("A05-"):
        return "A05:2025 인젝션 — SQL·OS 명령·XSS 등 악성 패턴이 입력에 포함되었습니다."
    if rid.startswith("A01-"):
        return "A01:2025 접근 제어 — 권한·리소스 경계를 넘는 요청 패턴입니다."
    if rid.startswith("A07-"):
        return "A07:2025 인증 결함 — 인증·세션·자격 증명 관련 의심 패턴입니다."
    return f"{rid} 규칙에 의해 탐지된 요청입니다. 증거 필드를 참고하세요."
