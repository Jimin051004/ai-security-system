# A07:2025 Authentication Failures — 테스트 페이로드 모음

> **테스트 환경:** WAF 프록시 `http://localhost:8000` 접속 후 실행  
> **브라우저 테스트:** F12 → Console 탭에 붙여넣기  
> **결과 확인:** HTTP `403` → WAF 차단 성공 ✅ / `200` or `401` → 서버까지 도달 ❌  
> **JWT 테스트:** 먼저 **사전 준비 헬퍼**를 실행해 토큰을 취득하세요.

---

## 사전 준비 — JWT 취득 헬퍼 (JWT 테스트 전 필수 실행)

```javascript
// ── 공통 헬퍼 (JWT 테스트 1~3 전에 반드시 먼저 실행) ──────────────────────
const b64url    = s => btoa(s).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
const b64urlObj = o => b64url(JSON.stringify(o));
const b64urlDec = s => {
  s = s.replace(/-/g,'+').replace(/_/g,'/');
  while (s.length % 4) s += '=';
  return JSON.parse(atob(s));
};

// Juice Shop 로그인 → 토큰 취득
const _loginRes = await fetch('/rest/user/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: 'admin@juice-sh.op', password: 'admin123' })
});
const _loginData = await _loginRes.json();
const TOKEN = _loginData?.authentication?.token;
if (!TOKEN) { console.error('로그인 실패 — Juice Shop이 실행 중인지 확인하세요'); }
else {
  const [HDR, PLD, SIG] = TOKEN.split('.');
  window._waf_hdr = HDR; window._waf_pld = PLD; window._waf_sig = SIG;
  console.log('✅ 토큰 취득 완료:', TOKEN.substring(0,40)+'...');
  console.log('   alg:', b64urlDec(HDR).alg);
}
```

---

## JWT-001 — alg:none 서명 검증 우회 `CRITICAL` ✅ 차단

> JWT 헤더의 `alg` 값을 `none`으로 변조 → 서버가 서명 검증 없이 토큰 수락  
> WAF는 Bearer 헤더를 Base64url 디코딩해 `alg:none`을 즉시 감지한다.

```javascript
// alg:none 헤더로 교체, 서명 파트 제거
const fakeHeader = b64urlObj({ alg: 'none', typ: 'JWT' });
const algnoneToken = `${fakeHeader}.${window._waf_pld}.`;

const r1 = await fetch('/api/Users', {
  headers: { 'Authorization': `Bearer ${algnoneToken}` }
});
console.log('JWT-001 alg:none →', r1.status === 403 ? '🔴 BLOCKED ✅' : `⚠️  PASSED (${r1.status})`);
```

```bash
# curl — alg:none 헤더 미리 계산된 값 사용
# eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0 = base64url({"alg":"none","typ":"JWT"})

TOKEN=$(curl -s -X POST http://localhost:8000/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@juice-sh.op","password":"admin123"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['authentication']['token'])")

PAYLOAD=$(echo $TOKEN | cut -d'.' -f2)
FAKE_HDR="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"

curl -i http://localhost:8000/api/Users \
  -H "Authorization: Bearer ${FAKE_HDR}.${PAYLOAD}."
# 기대 결과: HTTP/1.1 403
```

---

## JWT-002 — 서명 파트 누락 무서명 토큰 `HIGH` ✅ 차단

> 원본 헤더·페이로드는 유지하되 서명 부분을 완전히 제거한 `header.payload.` 형태  
> WAF가 Bearer 토큰을 분리해 서명 파트가 빈 문자열임을 감지한다.

```javascript
// 서명만 제거 (헤더·페이로드 원본 유지)
const nosigToken = `${window._waf_hdr}.${window._waf_pld}.`;

const r2 = await fetch('/api/Users', {
  headers: { 'Authorization': `Bearer ${nosigToken}` }
});
console.log('JWT-002 서명 누락 →', r2.status === 403 ? '🔴 BLOCKED ✅' : `⚠️  PASSED (${r2.status})`);
```

```bash
HEADER=$(echo $TOKEN | cut -d'.' -f1)
PAYLOAD=$(echo $TOKEN | cut -d'.' -f2)

curl -i http://localhost:8000/api/Users \
  -H "Authorization: Bearer ${HEADER}.${PAYLOAD}."
# 기대 결과: HTTP/1.1 403
```

---

## JWT-003 — payload 권한 변조 role:admin 삽입 `CRITICAL` ✅ 차단

> JWT payload의 `data.role` 값을 `"admin"`으로 변조  
> Juice Shop의 토큰 구조(`{"data":{"role":"admin",...}}`)를 파싱해 탐지한다.

```javascript
// payload 디코딩 → role:admin 삽입 → 재인코딩 (서명은 원본 유지)
const origPayload = b64urlDec(window._waf_pld);
const tamperedData = { ...origPayload.data, role: 'admin', isAdmin: true };
const tamperedPayload = { ...origPayload, data: tamperedData };
const tamperedToken = `${window._waf_hdr}.${b64urlObj(tamperedPayload)}.${window._waf_sig}`;

const r3 = await fetch('/api/Users', {
  headers: { 'Authorization': `Bearer ${tamperedToken}` }
});
console.log('JWT-003 role:admin →', r3.status === 403 ? '🔴 BLOCKED ✅' : `⚠️  PASSED (${r3.status})`);
```

```bash
# Python으로 payload 변조 후 curl 전송
python3 - <<'EOF'
import base64, json, subprocess, sys

token = subprocess.check_output(
  ['curl','-s','-X','POST','http://localhost:8000/rest/user/login',
   '-H','Content-Type: application/json',
   '-d','{"email":"admin@juice-sh.op","password":"admin123"}']
).decode()
tok = json.loads(token)['authentication']['token']
hdr, pld, sig = tok.split('.')

# payload 변조
pad = 4 - len(pld) % 4
decoded = json.loads(base64.b64decode(pld.replace('-','+').replace('_','/') + '='*pad))
decoded['data']['role'] = 'admin'
decoded['data']['isAdmin'] = True
new_pld = base64.b64encode(json.dumps(decoded).encode()).rstrip(b'=').replace(b'+',b'-').replace(b'/',b'_').decode()
tampered = f"{hdr}.{new_pld}.{sig}"
print(f"변조 토큰: {tampered[:60]}...")
subprocess.run(['curl','-i','http://localhost:8000/api/Users',
                '-H',f'Authorization: Bearer {tampered}'])
EOF
# 기대 결과: HTTP/1.1 403
```

---

## CRED-001 — 브루트포스 로그인 반복 `HIGH` ✅ 차단

> 동일 IP에서 `/rest/user/login`에 10회/60초 초과 POST → 11번째부터 차단  
> 인메모리 슬라이딩 윈도우 카운터로 IP별 요청 빈도 추적

```javascript
// 12회 연속 로그인 시도 — 11번째부터 403
(async () => {
  for (let i = 1; i <= 12; i++) {
    const r = await fetch('/rest/user/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'admin@juice-sh.op', password: `wrong${i}` })
    });
    const status = r.status === 403 ? '🔴 BLOCKED' : `⚪ ${r.status}`;
    console.log(`CRED-001 시도 ${String(i).padStart(2,'0')} → ${status}`);
    await new Promise(res => setTimeout(res, 200));
  }
})();
```

```bash
# curl — 12회 반복 (11번째부터 403 기대)
for i in $(seq 1 12); do
  printf "[%02d] " $i
  curl -s -o /dev/null -w "HTTP %{http_code}\n" \
    -X POST http://localhost:8000/rest/user/login \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"admin@juice-sh.op\",\"password\":\"wrong${i}\"}"
  sleep 0.2
done
# 기대 결과: [01]~[10] HTTP 401 | [11][12] HTTP 403
```

---

## CRED-002 — 크리덴셜 스터핑 다중 이메일 `HIGH` ✅ 차단

> 동일 IP에서 60초 내 5개 이상 다른 이메일로 로그인 시도  
> 인메모리 스터핑 스토어에 (timestamp, email) 누적 후 유니크 이메일 수로 탐지

```javascript
// 서로 다른 이메일 6개로 빠르게 로그인 시도 → 5번째부터 탐지
const stuffEmails = [
  'alice@example.com', 'bob@example.com', 'charlie@example.com',
  'dave@example.com',  'eve@example.com',  'frank@example.com'
];
(async () => {
  for (const email of stuffEmails) {
    const r = await fetch('/rest/user/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'Password1!' })
    });
    const status = r.status === 403 ? '🔴 BLOCKED' : `⚪ ${r.status}`;
    console.log(`CRED-002 ${email.padEnd(22)} → ${status}`);
    await new Promise(res => setTimeout(res, 150));
  }
})();
```

```bash
for email in alice@example.com bob@example.com charlie@example.com dave@example.com eve@example.com frank@example.com; do
  printf "%-28s " "$email"
  curl -s -o /dev/null -w "HTTP %{http_code}\n" \
    -X POST http://localhost:8000/rest/user/login \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${email}\",\"password\":\"Password1!\"}"
  sleep 0.15
done
# 기대 결과: 5번째 이메일(eve) 또는 6번째(frank)부터 HTTP 403
```

---

## CRED-003 — 약한·기본 패스워드 사용 `MEDIUM` ⚠️ 감지(차단 임계값 미달)

> 로그인 바디에 알려진 취약 패스워드(admin123, password, 123456 등) 포함 시 탐지  
> 기본 차단 임계값(HIGH)보다 낮은 MEDIUM 등급 — 감지 로그는 기록됨  
> ※ `WAF_BLOCK_MIN_SEVERITY=medium` 설정 시 차단으로 전환 가능

```javascript
// 알려진 약한 패스워드 5종 테스트
const weakPwds = ['admin123', 'password', '123456', 'letmein', 'qwerty'];
(async () => {
  for (const pw of weakPwds) {
    const r = await fetch('/rest/user/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'test@test.com', password: pw })
    });
    // MEDIUM → 403 차단 안 됨, 401 (인증 실패)로 서버 도달
    const status = r.status === 403 ? '🔴 BLOCKED' : `⚠️  DETECTED(${r.status})`;
    console.log(`CRED-003 password="${pw}" → ${status}`);
  }
})();
```

```bash
for pw in admin123 password 123456 letmein qwerty; do
  printf 'password=%-12s ' "$pw"
  curl -s -o /dev/null -w "HTTP %{http_code}\n" \
    -X POST http://localhost:8000/rest/user/login \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"test@test.com\",\"password\":\"${pw}\"}"
done
# MEDIUM 등급 — 기본 설정에서는 403 대신 401 반환 (탐지는 대시보드에 기록)
```

> **차단으로 전환:** WAF 대시보드 `/__waf/dashboard` → Block Min Severity → `medium` 변경

---

## SESS-001 — 세션 ID URL 노출 `MEDIUM` ⚠️ 감지(차단 임계값 미달)

> URL 쿼리스트링에 `token=`, `session=`, `jwt=` 등의 민감 파라미터 포함 시 탐지  
> 세션 고정(Session Fixation) 및 Referer 헤더를 통한 토큰 유출 위험

```javascript
// ?token= 포함 요청
const r7a = await fetch(`/rest/user/whoami?token=${window._waf_pld || 'ABCDEFGHIJKLMNOP1234'}`);
console.log('SESS-001 ?token=  →', r7a.status === 403 ? '🔴 BLOCKED' : `⚠️  DETECTED(${r7a.status})`);

// ?session= 포함 요청
const r7b = await fetch('/api/Users?session=ABCDEF1234567890ABCDEF1234567890');
console.log('SESS-001 ?session= →', r7b.status === 403 ? '🔴 BLOCKED' : `⚠️  DETECTED(${r7b.status})`);

// ?jwt= 포함 요청
const r7c = await fetch(`/rest/user/whoami?jwt=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.ABCD1234`);
console.log('SESS-001 ?jwt=    →', r7c.status === 403 ? '🔴 BLOCKED' : `⚠️  DETECTED(${r7c.status})`);
```

```bash
# ?token= 쿼리스트링에 토큰 노출
curl -i "http://localhost:8000/rest/user/whoami?token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.FAKE_PAYLOAD_1234567890"

# ?session= 쿼리스트링
curl -i "http://localhost:8000/api/Users?session=ABCDEF1234567890ABCDEF1234567890"
# MEDIUM 등급 — 기본 설정에서는 탐지 기록만
```

---

## ENUM-001 — 계정 열거 다중 이메일 스캔 `HIGH` ✅ 차단

> 동일 IP에서 30초 내 3개 이상 서로 다른 이메일로 빠르게 로그인 시도  
> 계정 존재 여부를 파악하려는 스캐닝 패턴 → 3번째 이메일 누적 시 탐지·차단

```javascript
// 30초 내 다른 이메일 4개로 빠르게 시도 → 3번째부터 탐지
const enumEmails = [
  'admin@juice-sh.op',
  'jim@juice-sh.op',
  'bender@juice-sh.op',
  'morty@juice-sh.op'   // ← 4번째: ENUM-001 차단
];
(async () => {
  for (const email of enumEmails) {
    const r = await fetch('/rest/user/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'wrongpassword' })
    });
    const status = r.status === 403 ? '🔴 BLOCKED ✅' : `⚪ ${r.status}`;
    console.log(`ENUM-001 ${email.padEnd(26)} → ${status}`);
    // 딜레이 없음 — 빠른 스캔 패턴 재현
  }
})();
```

```bash
# 30초 이내 딜레이 없이 실행
for email in admin@juice-sh.op jim@juice-sh.op bender@juice-sh.op morty@juice-sh.op; do
  printf "%-30s " "$email"
  curl -s -o /dev/null -w "HTTP %{http_code}\n" \
    -X POST http://localhost:8000/rest/user/login \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${email}\",\"password\":\"wrongpassword\"}"
done
# 기대 결과: 3~4번째 이메일부터 HTTP 403
```

---

## 전체 자동 실행 스크립트 (브라우저 콘솔)

> **순서:** ① 사전 준비 헬퍼 실행 → ② 아래 스크립트 붙여넣기  
> JWT-001~003은 헬퍼 실행 후 토큰이 `window._waf_hdr/pld/sig`에 저장된 상태에서만 동작

```javascript
(async () => {
  const results = [];
  const check = (name, status, expectBlock = true) => {
    const blocked = status === 403;
    const icon = blocked ? '🔴 BLOCKED' : (expectBlock ? '⚠️  PASSED ' : '📋 DETECT ');
    const mark  = (expectBlock && blocked) || (!expectBlock && !blocked) ? '✅' : '❌';
    const msg   = `${icon} [${status}] ${name} ${mark}`;
    results.push(msg);
    console.log(msg);
  };

  // ── JWT 테스트 (토큰 필요) ──────────────────────────────────────────────
  if (!window._waf_hdr) {
    console.warn('⛔ 사전 준비 헬퍼를 먼저 실행하세요!');
  } else {
    const b64urlObj = o => btoa(JSON.stringify(o)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
    const b64urlDec = s => {
      s = s.replace(/-/g,'+').replace(/_/g,'/');
      while (s.length % 4) s += '=';
      return JSON.parse(atob(s));
    };

    // JWT-001: alg:none
    const algNoneHdr = b64urlObj({ alg: 'none', typ: 'JWT' });
    let r = await fetch('/api/Users', {
      headers: { 'Authorization': `Bearer ${algNoneHdr}.${window._waf_pld}.` }
    });
    check('JWT-001 alg:none', r.status);

    // JWT-002: 서명 누락
    r = await fetch('/api/Users', {
      headers: { 'Authorization': `Bearer ${window._waf_hdr}.${window._waf_pld}.` }
    });
    check('JWT-002 서명 누락', r.status);

    // JWT-003: role:admin 삽입
    const orig = b64urlDec(window._waf_pld);
    const tampered = { ...orig, data: { ...orig.data, role: 'admin', isAdmin: true } };
    const tPld = b64urlObj(tampered);
    r = await fetch('/api/Users', {
      headers: { 'Authorization': `Bearer ${window._waf_hdr}.${tPld}.${window._waf_sig}` }
    });
    check('JWT-003 role:admin', r.status);
  }

  await new Promise(res => setTimeout(res, 300));

  // ── SESS-001: 세션 URL 노출 (MEDIUM — 차단 안 될 수 있음) ──────────────
  let r = await fetch('/rest/user/whoami?token=eyJhbGciOiJSUzI1NiJ9.ABCDEF1234567890');
  check('SESS-001 세션 URL 노출', r.status, false);

  await new Promise(res => setTimeout(res, 300));

  // ── CRED-003: 약한 패스워드 (MEDIUM) ───────────────────────────────────
  r = await fetch('/rest/user/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'test@test.com', password: 'admin123' })
  });
  check('CRED-003 약한 패스워드', r.status, false);

  await new Promise(res => setTimeout(res, 300));

  // ── ENUM-001: 계정 열거 (30초 내 3+ 이메일 → HIGH) ─────────────────────
  const enumEmails = ['scan1@example.com','scan2@example.com','scan3@example.com','scan4@example.com'];
  for (const email of enumEmails) {
    r = await fetch('/rest/user/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'wrong' })
    });
    check(`ENUM-001 ${email}`, r.status, enumEmails.indexOf(email) >= 2);
  }

  await new Promise(res => setTimeout(res, 300));

  // ── CRED-002: 크리덴셜 스터핑 (60초 내 5+ 이메일) ──────────────────────
  const stuffEmails = ['a@x.com','b@x.com','c@x.com','d@x.com','e@x.com','f@x.com'];
  for (const email of stuffEmails) {
    r = await fetch('/rest/user/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'Pass1!' })
    });
    check(`CRED-002 ${email}`, r.status, stuffEmails.indexOf(email) >= 4);
    await new Promise(res => setTimeout(res, 100));
  }

  await new Promise(res => setTimeout(res, 300));

  // ── CRED-001: 브루트포스 (10회 초과 → HIGH) ────────────────────────────
  for (let i = 1; i <= 12; i++) {
    r = await fetch('/rest/user/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'brute@test.com', password: `wrong${i}` })
    });
    if (i >= 10) check(`CRED-001 브루트포스 ${i}회`, r.status, i > 10);
    await new Promise(res => setTimeout(res, 150));
  }

  // ── 결과 요약 ───────────────────────────────────────────────────────────
  console.log('\n══ 결과 요약 ════════════════════════════════');
  results.forEach(m => console.log(m));
  console.log('════════════════════════════════════════════');
  console.log('📊 WAF 대시보드: http://localhost:8000/__waf/dashboard');
})();
```

---

## 규칙별 차단 요약

| Rule | 탐지 내용 | 심각도 | 기본 차단 |
|------|-----------|--------|-----------|
| JWT-001 | alg:none — 서명 검증 우회 | CRITICAL | ✅ 차단 |
| JWT-002 | 서명 파트 누락 | HIGH | ✅ 차단 |
| JWT-003 | payload role:admin 삽입 | CRITICAL | ✅ 차단 |
| CRED-001 | 브루트포스 10회/60초 | HIGH | ✅ 차단 |
| CRED-002 | 크리덴셜 스터핑 5+ 이메일 | HIGH | ✅ 차단 |
| CRED-003 | 약한·기본 패스워드 | MEDIUM | ⚠️ 감지만 |
| SESS-001 | 세션 ID URL 노출 | MEDIUM | ⚠️ 감지만 |
| ENUM-001 | 계정 열거 3+ 이메일/30초 | HIGH | ✅ 차단 |

> **MEDIUM 감지만** 항목을 차단으로 전환하려면:  
> `/__waf/dashboard` → Block Min Severity → `medium` 으로 변경

---

*파일: `docs/a07_payload.md` | 대응 모듈: `owasp/a07.py`*
