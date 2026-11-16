# 📋 Zero-Transmission TOTP Authenticator: Technical Specification & Implementation Plan

> **문서 목적**: 외부 서버로의 데이터 전송 없이 브라우저 로컬(Client-side Web Crypto API)에서 완결되는 Time-based One-Time Password (TOTP) 2단계 인증 서비스의 아키텍처, 핵심 보안 체크포인트 및 구현 명세를 정의합니다.

---

## 📌 1. 개요 (Overview)

본 프로젝트는 **Zero-Transmission 원칙**을 엄격히 준수하여 모든 암호학적 키 생성 및 HMAC-SHA1 연산을 브라우저의 `window.crypto`를 통해 로컬에서 직접 처리하는 클라이언트 완결형 모바일 OTP 시스템을 구현합니다.

```
[비밀 키 (Base32 160-bit Secret)]  +  [현재 시각 에포크 (T = ⌊UnixTime / 30⌋)]
                   │
                   ▼   Web Crypto API (crypto.subtle) 로컬 HMAC-SHA1 연산
           [6자리 실시간 OTP 번호]  <─── 스마트폰 앱과 100% 동일 동기화
```

- **프로젝트 구성**: 3개 핵심 파일 구조 분리 (`index.html`, `src/App.jsx`, `src/App.css`)
- **앱 컨셉**: 실전 로그인 시뮬레이터 (1단계 ID/PW 인증 $\rightarrow$ 2단계 TOTP 모달 검증 $\rightarrow$ 보안 관리자 대시보드 인가)
- **표준 규격**: RFC 6238 (TOTP), RFC 4226 (HOTP), RFC 4648 (Base32)

---

## ✅ 2. 4대 완성 기준 (Four Completion Criteria)

### 1. 안전한 비밀 키 생성 (Secure Secret Key Generation)
- **발급 메커니즘**: 단 한 번의 버튼 클릭으로 암호학적 엔트로피 풀을 새로 생성하고 새로운 Base32 비밀 키를 발급합니다.
- **보안 및 호환성 규격**: 호환성과 보안성의 균형을 위해 **160비트(20바이트)**의 안전한 난수 데이터를 사용합니다.
- **문자 집합**: RFC 4648 Base32 (`ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`)

### 2. QR 코드 연동 (QR Code Integration - `otpauth://`)
- **표준 URI 포맷**:
  $$\text{otpauth://totp/Issuer:Account?secret=SECRET\&issuer=Issuer}$$
- **연동 기능**: DOM 상에 스캔 가능한 QR 코드를 직접 생성(SVG/Canvas)하여, 사용자가 스마트폰 표준 인증기 앱(Google Authenticator, Microsoft Authenticator, 2FAS, Authy 등)으로 즉시 등록할 수 있도록 지원합니다.

### 3. 실시간 동기화 및 2FA 보안 분리 (Real-Time Synchronization & Possession Factor)
- **타이밍 에포크 (Timing Epoch)**: 표준 30초 UNIX 타임스탬프 윈도우와 내부 백그라운드에서 동기화됩니다.
  $$T = \lfloor \text{Current Time (Seconds)} / 30 \rfloor$$
- **보안 분리 원칙 (Out-of-Band Possession Factor)**: 실시간 OTP 번호와 동기화 타이머는 **웹 브라우저 화면에 출력하지 않습니다**. 웹 화면에 OTP 코드가 출력되면 2단계 인증(소유 기반 인증)의 본질적 보안 가치가 상실되므로, 코드는 오직 사용자의 **스마트폰 Authenticator 앱에서만 생성·확인**되며 웹 시스템은 검증 시점에만 백그라운드로 동기화 계산을 수행합니다.

### 4. 코드 검증 (Code Verification)
- **검증 로직**: 사용자가 입력한 6자리 코드와 로컬에서 계산된 TOTP 값을 비교하여 일치 여부를 판정합니다.
- **시계 오차 허용 (Clock-Drift Tolerance)**: 기기 간의 미세한 시간 불일치로 인한 인증 거부를 방지하기 위해 $\pm 1$ 타임스텝 윈도우(직전 30초, 현재 30초, 다음 30초 구간)를 자동 확인합니다.
  - $T - 1$ (직전 30초 구간 - 시계 지연 허용)
  - $T$ (현재 활성 구간 - 오차 0초)
  - $T + 1$ (다음 30초 구간 - 시계 빠름 허용)

---

## 🛡️ 3. 2대 필수 사이버보안 체크포인트 (Two Essential Cybersecurity Checkpoints)

### 1. `Math.random()` 절대 금지 원칙 (Prohibition of Math.random())
- **규칙**: 일반 의사 난수 생성기(`Math.random()`)는 예측 가능하므로 암호학적 키 생성 연산에 절대 사용할 수 없습니다.
- **강제 조항**: 모든 엔트로피는 오직 브라우저 내장 암호학적 난수 생성기인 `window.crypto.getRandomValues()`로부터만 공급받아야 합니다.

### 2. Zero-Transmission 원칙 (무전송 원칙)
- **규칙**: 비밀 키와 HMAC-SHA1 서명 연산 결과는 절대로 클라이언트 기기 외부로 나가거나 외부 API 서버(예: 외부 QR 생성 API 등)와 통신해서는 안 됩니다.
- **강제 조항**: 브라우저 내장 `window.crypto.subtle` Web Crypto API를 통해 네이티브로 처리됩니다.
- **검증 절차**: 브라우저 개발자 도구(`F12`) $\rightarrow$ **Network (네트워크)** 탭을 열어 외부 서버로 비밀 키 및 서명 페이로드가 유출되지 않음(외부 요청 0건)을 입증할 수 있습니다.

---

## 🏗️ 4. 3개 분리 파일 아키텍처 (Three-File Architecture)

```
26-w11-mobile-otp/
├── index.html         # [1] HTML: 엔트리포인트 및 보안 메타데이터
├── src/
│   ├── App.jsx        # [2] JS/JSX: TOTP 암호화 엔진 + 실전 로그인/검증 시뮬레이터
│   └── App.css        # [3] CSS: 다크 테마 및 반응형 UI 스타일시트
```

### 1) [index.html](file:///d:/repo/26-w11-mobile-otp/index.html)
- 뷰포트 및 브라우저 메타데이터 정의
- React 루트 마운트 DOM (`<div id="root"></div>`)

### 2) [src/App.jsx](file:///d:/repo/26-w11-mobile-otp/src/App.jsx)
- **Crypto Module**:
  - `generateBase32Secret(20)`: 160-bit CSPRNG 비밀 키 생성
  - `base32ToBytes(secret)`: Base32 디코더
  - `computeTOTP(secret, timeStep)`: 8바이트 Big-Endian 버퍼 + HMAC-SHA1 + Dynamic Truncation
  - `verifyTOTPCode(input, secret, currentStep)`: $\pm 1$ 스텝 허용 검증 엔진
- **UI Components & Tabs**:
  - `Tab 1: 실전 로그인 시뮬레이터`: 1단계 ID/PW $\rightarrow$ 2단계 6자리 OTP 모달 $\rightarrow$ 관리자 대시보드 & 실시간 감사 로그
  - `Tab 2: 2FA 발급 및 실시간 동기화 센터`: 키 발급, `qrcode.react` 인라인 SVG QR, 30초 원형 타이머, 실시간 OTP
  - `Tab 3: 사이버보안 체크포인트 & 무전송 검증`: PRNG vs CSPRNG 설명, F12 검증 가이드, RFC 6238 원리

### 3) [src/App.css](file:///d:/repo/26-w11-mobile-otp/src/App.css)
- 사이버보안 다크 테마 및 글래스모피즘 스타일
- 6자리 개별 OTP 입력 필드 인터랙션 (포커스 링, 에러 쉐이크 애니메이션)
- SVG 원형 카운트다운 타이머 및 반응형 그리드 레이아웃

---

## 📈 5. 단계별 실행 계획 (Implementation Roadmap)

| 단계 | 목표 | 주요 작업 내용 | 상태 |
|---|---|---|:---:|
| **Phase 1** | 코어 암호화 엔진 구축 | - RFC 4648 Base32 인코딩/디코딩 구현<br>- `window.crypto.getRandomValues()` 기반 160비트 난수 생성<br>- `crypto.subtle` 기반 HMAC-SHA1 및 RFC 4226 Dynamic Truncation 검증 | ✅ 완료 |
| **Phase 2** | UI 3개 파일 분리 & QR 연동 | - `index.html`, `src/App.jsx`, `src/App.css` 구조화<br>- `otpauth://` 표준 URI 및 DOM 인라인 SVG QR 렌더링<br>- 30초 주기 동기화 루프 및 원형 타이머 UI | ✅ 완료 |
| **Phase 3** | 실전 로그인 시뮬레이터 & 검증 | - 1단계 자격증명 폼 $\rightarrow$ 2단계 6자리 분할 OTP 입력 모달 구현<br>- $\pm 1$ 타임스텝($T-1, T, T+1$) 시계 오차 허용 판정<br>- 인증 인가 대시보드 및 실시간 보안 감사 로그 연동 | ✅ 완료 |
| **Phase 4** | 보안 검증 및 빌드/배포 | - `oxlint` 린트 및 `vite build` 무결성 검증<br>- F12 Network 탭 무전송 검증 확인<br>- Git 커밋(`GEMINI.md` 규칙) 및 배포 준비 | ✅ 완료 |

---

## 🧪 6. 보안 점검 및 테스트 체크리스트 (Verification Checklist)

- [x] **CSPRNG 검증**: 키 생성 시 `Math.random()` 호출이 없으며 `crypto.getRandomValues()`만 사용하는가?
- [x] **RFC 6238 정밀도**: 테스트 벡터 및 실제 스마트폰 Authenticator 앱과 6자리 숫자가 오차 없이 일치하는가?
- [x] **Zero-Transmission**: 개발자 도구(F12) Network 탭에서 키 생성 및 검증 시 외부 API 호출이 0건인가?
- [x] **시계 오차 허용**: 직전($T-1$) 및 다음($T+1$) 타임스텝 코드 입력 시 정상적으로 인가 판정되는가?
- [x] **3개 파일 분리**: HTML, JS/JSX, CSS의 관심사 분리가 명확하고 유지보수 가능한가?

