# OWASP Top 10:2025 — PDF 기준 정리 (Juice Shop 챌린지 매핑)

> **출처:** 사용자 제공 PDF `OWASP TOP 10 2025.pdf` (`/Users/jimin/Downloads/OWASP TOP 10 2025.pdf`)에서 추출한 표를 Markdown으로 옮긴 것입니다.  
> **용도:** 질문·구현 우선순위를 잡을 때 **이 파일과 함께** 참고합니다. 상세 서술형 가이드는 `docs/OWASP_TOP10_2025.md` 를 봅니다.  
> **난이도:** PDF에 표기된 숫자(추정 1~5, 낮을수록 쉬움에 가깝게 쓰인 경우가 많음).

---

## A01:2025 — Broken Access Control

| 챌린지 (영문 / 검색어) | 난이도 |
|------------------------|--------|
| Admin Section | 1 |
| View Basket | 2 |
| Basket Access | 2 |
| Five-Star Feedback | 2 |
| Manipulate Basket | 3 |
| Privacy Policy (Type) | 3 |
| SSRF Tier 1 | 3 |
| SSRF Tier 2 | 4 |
| Bjoern's Favorite Pet | 3 |

---

## A02:2025 — Security Misconfiguration

| 챌린지 (영문 / 검색어) | 난이도 |
|------------------------|--------|
| Error Handling | 1 |
| Deprecated Endpoint | 1 |
| Privacy Policy (Hidden) | 1 |
| XXE Tier 1 | 3 |
| XXE Tier 2 | 4 |
| Security Policy | 2 |
| Jobs Portal | 3 |

---

## A03:2025 — Software Supply Chain Failures

| 챌린지 (영문 / 검색어) | 난이도 |
|------------------------|--------|
| Vulnerable Library | 1 |
| Frontend Fraud | 2 |
| Metadata Leak | 3 |
| Poison Dependencies | 4 |
| Supply Chain Attack | 5 |

---

## A04:2025 — Cryptographic Failures

| 챌린지 (영문 / 검색어) | 난이도 |
|------------------------|--------|
| Weak Password Hashing | 2 |
| Cleartext Storage | 2 |
| MD5 Hashing | 2 |
| Login Amy | 3 |
| Premium Paywall | 3 |
| Forgotten Password | 4 |

---

## A05:2025 — Injection

| 챌린지 (영문 / 검색어) | 난이도 |
|------------------------|--------|
| Login Admin | 2 |
| User Search (SQLi) | 2 |
| NoSQL Injection | 4 |
| OS Command Injection | 5 |
| Login Bjoern | 3 |
| Database Schema | 3 |
| LDAP Injection | 4 |

---

## A06:2025 — Insecure Design

| 챌린지 (영문 / 검색어) | 난이도 |
|------------------------|--------|
| Negative Order | 3 |
| Christmas Special | 3 |
| Forged Feedback | 3 |
| Price Manipulation | 3 |
| Forged Coupon | 4 |
| Zero Stars | 3 |

---

## A07:2025 — Authentication Failures

| 챌린지 (영문 / 검색어) | 난이도 |
|------------------------|--------|
| Login Jim | 3 |
| Login Bender | 3 |
| Password Strength | 2 |
| Brute Force Adalberto | 3 |
| 2FA Bypass | 4 |
| Reset Password Jim | 3 |

---

## A08:2025 — Software or Data Integrity Failures

| 챌린지 (영문 / 검색어) | 난이도 |
|------------------------|--------|
| JWT Unsigned | 3 |
| JWT Manipulation | 4 |
| Insecure Deserialization | 5 |
| Bjoern's Order | 3 |
| File Integrity | 4 |

---

## A09:2025 — Logging & Alerting Failures

| 챌린지 (영문 / 검색어) | 난이도 |
|------------------------|--------|
| Mass Exploitation | 3 |
| Log Management | 3 |
| Access Log Leak | 4 |
| Bruteforce Detection | 4 |

---

## A10:2025 — Mishandling of Exceptional Conditions

| 챌린지 (영문 / 검색어) | 난이도 |
|------------------------|--------|
| Informative Error | 1 |
| Stack Trace | 2 |
| Out of Memory | 3 |
| Fail Open Authentication | 4 |

---

## 같이 보면 좋은 문서

| 파일 | 내용 |
|------|------|
| `docs/OWASP_TOP10_2025.md` | 항목별 개요·통계·시나리오 (긴 가이드) |
| `docs/OWASP_TOP10_2025_Guide.md` | 추가 가이드 (있는 경우) |
| `.cursor/rules/owasp-top10-2025-workflow.mdc` | 모듈 매핑·작업 순서 규칙 |

공식 목록: [OWASP Top 10:2025](https://owasp.org/Top10/2025/)
