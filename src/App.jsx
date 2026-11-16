import { useState, useEffect, useRef, useCallback } from 'react'
import { QRCodeSVG } from 'qrcode.react'
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Key,
  QrCode,
  Clock,
  RefreshCw,
  Copy,
  Check,
  LogIn,
  LogOut,
  Lock,
  User,
  ArrowRight,
  Smartphone,
  Terminal
} from 'lucide-react'
import './App.css'

// ==========================================
// 🛡️ RFC 4648 Base32 & RFC 6238 TOTP Engine
// (100% Client-side Web Crypto API, Zero-Transmission)
// ==========================================
const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

/**
 * 암호학적 안전 난수 생성 (window.crypto.getRandomValues)
 * 160비트(20바이트) 엔트로피 풀을 사용해 Base32 비밀 키 생성
 */
function generateBase32Secret(byteLength = 20) {
  const bytes = new Uint8Array(byteLength)
  window.crypto.getRandomValues(bytes)

  let bits = 0
  let value = 0
  let output = ''

  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i]
    bits += 8
    while (bits >= 5) {
      output += BASE32_CHARS[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) {
    output += BASE32_CHARS[(value << (5 - bits)) & 31]
  }
  return output
}

/**
 * Base32 문자열을 바이트 배열(Uint8Array)로 디코딩
 */
function base32ToBytes(base32Str) {
  const cleanStr = base32Str.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '')
  let bits = 0
  let value = 0
  const bytes = []

  for (let i = 0; i < cleanStr.length; i++) {
    const val = BASE32_CHARS.indexOf(cleanStr[i])
    if (val === -1) continue
    value = (value << 5) | val
    bits += 5
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255)
      bits -= 8
    }
  }
  return new Uint8Array(bytes)
}

/**
 * 특정 타임스텝(timeStep)에 대한 6자리 TOTP 코드 연산 (RFC 6238 / RFC 4226)
 * Web Crypto API (HMAC-SHA1) 활용
 */
async function computeTOTP(secretBase32, timeStep) {
  try {
    const keyBytes = base32ToBytes(secretBase32)
    if (keyBytes.length === 0) return '------'

    const cryptoKey = await window.crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: 'SHA-1' },
      false,
      ['sign']
    )

    // 64비트(8바이트) 빅엔디안 카운터 버퍼 구성
    const counterBuffer = new ArrayBuffer(8)
    const dataView = new DataView(counterBuffer)
    dataView.setBigUint64(0, BigInt(timeStep), false)

    // HMAC-SHA1 서명 생성
    const signature = await window.crypto.subtle.sign('HMAC', cryptoKey, counterBuffer)
    const hmac = new Uint8Array(signature)

    // Dynamic Truncation (동적 절단, RFC 4226)
    const offset = hmac[hmac.length - 1] & 0x0f
    const binary =
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff)

    // 6자리 코드 추출
    const otp = (binary % 1000000).toString().padStart(6, '0')
    return otp
  } catch (err) {
    console.error('TOTP 연산 오류:', err)
    return '------'
  }
}

/**
 * ±1 스텝 시계 오차(Clock-Drift) 허용 검증 (RFC 6238)
 * T-1 (과거 30초), T (현재), T+1 (미래 30초) 구간 확인
 */
async function verifyTOTPCode(inputCode, secretBase32, currentStep) {
  const cleanCode = inputCode.trim()
  if (cleanCode.length !== 6 || !/^\d{6}$/.test(cleanCode)) {
    return { valid: false, reason: '6자리 숫자를 입력하세요.' }
  }

  const stepsToCheck = [
    { step: currentStep, delta: 0, label: '현재 구간 (오차 0초)' },
    { step: currentStep - 1, delta: -30, label: '직전 구간 (시계 지연 -30초 허용)' },
    { step: currentStep + 1, delta: +30, label: '다음 구간 (시계 빠름 +30초 허용)' }
  ]

  for (const item of stepsToCheck) {
    const computed = await computeTOTP(secretBase32, item.step)
    if (computed === cleanCode) {
      return {
        valid: true,
        matchedStep: item.step,
        delta: item.delta,
        label: item.label
      }
    }
  }

  return {
    valid: false,
    reason: '인증 번호가 일치하지 않거나 30초 유효 기간이 만료되었습니다.'
  }
}

export default function App() {
  // --- 활성 탭 관리: 'simulator' (실전 로그인), 'setup' (2FA 설정/모니터), 'security' (보안 체크포인트) ---
  const [activeTab, setActiveTab] = useState('simulator')

  // --- 발급자 및 계정 설정 ---
  const [issuer, setIssuer] = useState('ZeroAuth')
  const [account, setAccount] = useState('admin@k-cybersec.ac.kr')
  const [secretKey, setSecretKey] = useState(() => generateBase32Secret(20))

  // --- 실시간 타이머 및 TOTP 상태 ---
  const [currentStep, setCurrentStep] = useState(() => Math.floor(Date.now() / 1000 / 30))
  const [remainingSeconds, setRemainingSeconds] = useState(() => 30 - (Math.floor(Date.now() / 1000) % 30))
  const [activeOtp, setActiveOtp] = useState('------')
  const [prevOtp, setPrevOtp] = useState('------')
  const [nextOtp, setNextOtp] = useState('------')
  const [copiedKey, setCopiedKey] = useState(false)
  const [copiedOtp, setCopiedOtp] = useState(false)
  const [copiedUri, setCopiedUri] = useState(false)

  // --- 로그인 시뮬레이터 상태 ---
  // loginStage: 'credentials' (1단계 ID/PW) | '2fa_modal' (2단계 OTP 모달) | 'dashboard' (인증 성공 대시보드)
  const [loginStage, setLoginStage] = useState('credentials')
  const [username, setUsername] = useState('cybersec_admin')
  const [password, setPassword] = useState('password123!')
  const [otpInputs, setOtpInputs] = useState(['', '', '', '', '', ''])
  const [isVerifying, setIsVerifying] = useState(false)
  const [verificationResult, setVerificationResult] = useState(null)
  const [sessionData, setSessionData] = useState(null)
  const [auditLogs, setAuditLogs] = useState(() => [
    {
      id: 1,
      timestamp: new Date().toLocaleTimeString(),
      event: '시스템 초기화 완료 (Zero-Transmission 활성화)',
      status: 'info'
    }
  ])

  // OTP 6자리 입력 ref 배열
  const otpInputRefs = useRef([])

  // --- URI 계산 (RFC 6238 규격) ---
  const otpauthUri = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secretKey}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`

  // 새 비밀 키 생성
  const handleRegenerateKey = useCallback(() => {
    const newKey = generateBase32Secret(20)
    setSecretKey(newKey)
    setAuditLogs((prev) => [
      {
        id: Date.now(),
        timestamp: new Date().toLocaleTimeString(),
        event: '새 Base32 비밀 키 생성 (160비트 암호학적 엔트로피 풀 발급)',
        status: 'warning'
      },
      ...prev
    ])
  }, [])

  // 1초 주기로 실시간 타이머 및 타임스텝 업데이트
  useEffect(() => {
    const interval = setInterval(() => {
      const nowSec = Math.floor(Date.now() / 1000)
      const step = Math.floor(nowSec / 30)
      const remain = 30 - (nowSec % 30)

      setRemainingSeconds(remain)
      setCurrentStep(step)
    }, 1000)

    return () => clearInterval(interval)
  }, [])

  // 타임스텝 또는 비밀 키 변경 시 6자리 OTP 재연산 (T-1, T, T+1)
  useEffect(() => {
    let isCancelled = false

    async function updateOtps() {
      const [current, past, future] = await Promise.all([
        computeTOTP(secretKey, currentStep),
        computeTOTP(secretKey, currentStep - 1),
        computeTOTP(secretKey, currentStep + 1)
      ])
      if (!isCancelled) {
        setActiveOtp(current)
        setPrevOtp(past)
        setNextOtp(future)
      }
    }

    updateOtps()
    return () => {
      isCancelled = true
    }
  }, [secretKey, currentStep])

  // 클립보드 복사 헬퍼
  const handleCopy = (text, setCopiedFn) => {
    navigator.clipboard.writeText(text)
    setCopiedFn(true)
    setTimeout(() => setCopiedFn(false), 2000)
  }

  // --- 로그인 폼 제출 (1단계 완료 -> 2단계 모달 오픈) ---
  const handleCredentialsSubmit = (e) => {
    e.preventDefault()
    if (!username.trim() || !password.trim()) {
      alert('아이디와 비밀번호를 입력해주세요.')
      return
    }
    setOtpInputs(['', '', '', '', '', ''])
    setVerificationResult(null)
    setLoginStage('2fa_modal')

    // 첫 번째 OTP 인풋에 자동 포커스
    setTimeout(() => {
      otpInputRefs.current[0]?.focus()
    }, 100)
  }

  // --- OTP 6자리 입력 핸들러 ---
  const handleOtpChange = (index, value) => {
    const cleanVal = value.replace(/\D/g, '')
    if (!cleanVal) {
      const newInputs = [...otpInputs]
      newInputs[index] = ''
      setOtpInputs(newInputs)
      return
    }

    // 여러 자리(붙여넣기 등)가 들어온 경우
    if (cleanVal.length > 1) {
      handleOtpPaste(cleanVal)
      return
    }

    const newInputs = [...otpInputs]
    newInputs[index] = cleanVal
    setOtpInputs(newInputs)

    // 다음 인풋으로 자동 포커스 이동
    if (index < 5 && cleanVal) {
      otpInputRefs.current[index + 1]?.focus()
    }
  }

  // 백스페이스 및 화살표 키 네비게이션
  const handleOtpKeyDown = (index, e) => {
    if (e.key === 'Backspace' && !otpInputs[index] && index > 0) {
      otpInputRefs.current[index - 1]?.focus()
    } else if (e.key === 'ArrowLeft' && index > 0) {
      otpInputRefs.current[index - 1]?.focus()
    } else if (e.key === 'ArrowRight' && index < 5) {
      otpInputRefs.current[index + 1]?.focus()
    } else if (e.key === 'Enter') {
      executeVerification()
    }
  }

  // 6자리 붙여넣기 지원
  const handleOtpPaste = (pastedText) => {
    const digits = pastedText.replace(/\D/g, '').slice(0, 6).split('')
    const newInputs = ['', '', '', '', '', '']
    digits.forEach((d, i) => {
      newInputs[i] = d
    })
    setOtpInputs(newInputs)
    const nextIdx = Math.min(digits.length, 5)
    otpInputRefs.current[nextIdx]?.focus()
  }

  // 빠른 테스트: 현재 PC 발급 코드를 6자리 인풋에 자동 채우기
  const handleQuickFill = () => {
    if (activeOtp && activeOtp !== '------') {
      const digits = activeOtp.split('')
      setOtpInputs(digits)
      otpInputRefs.current[5]?.focus()
    }
  }

  // --- 2FA 검증 실행 ---
  const executeVerification = async () => {
    const fullCode = otpInputs.join('')
    if (fullCode.length !== 6) {
      setVerificationResult({
        valid: false,
        reason: '6자리 인증 코드를 모두 입력해 주세요.'
      })
      return
    }

    setIsVerifying(true)
    setVerificationResult(null)

    // 실전 환경 느낌의 가벼운 딜레이 (로컬 Web Crypto 검증 시뮬레이션)
    setTimeout(async () => {
      const result = await verifyTOTPCode(fullCode, secretKey, currentStep)
      setIsVerifying(false)
      setVerificationResult(result)

      if (result.valid) {
        const newSession = {
          user: username,
          authenticatedAt: new Date().toLocaleTimeString(),
          matchedWindow: result.label,
          sessionToken: 'zeroauth_session_' + Math.random().toString(36).substring(2, 10),
          zeroTransmissionVerified: true
        }
        setSessionData(newSession)

        setAuditLogs((prev) => [
          {
            id: Date.now(),
            timestamp: new Date().toLocaleTimeString(),
            event: `2단계 인증 성공 (${result.label}) - 사용자 [${username}] 로그인 인가`,
            status: 'success'
          },
          ...prev
        ])

        // 성공 후 대시보드로 이동
        setTimeout(() => {
          setLoginStage('dashboard')
        }, 800)
      } else {
        setAuditLogs((prev) => [
          {
            id: Date.now(),
            timestamp: new Date().toLocaleTimeString(),
            event: `2단계 인증 실패: 코드 [${fullCode}] 불일치 또는 유효시간 경과`,
            status: 'danger'
          },
          ...prev
        ])
      }
    }, 200)
  }

  // 로그아웃
  const handleLogout = () => {
    setLoginStage('credentials')
    setSessionData(null)
    setVerificationResult(null)
    setOtpInputs(['', '', '', '', '', ''])
    setAuditLogs((prev) => [
      {
        id: Date.now(),
        timestamp: new Date().toLocaleTimeString(),
        event: `사용자 [${username}] 로그아웃 완료`,
        status: 'info'
      },
      ...prev
    ])
  }

  // 원형 타이머 계산
  const timerPercent = (remainingSeconds / 30) * 100
  const timerColor = remainingSeconds <= 5 ? '#ef4444' : remainingSeconds <= 10 ? '#f59e0b' : '#10b981'

  return (
    <div className="app-container">
      {/* ================= HEADER ================= */}
      <header className="app-header">
        <div className="header-brand">
          <div className="brand-icon-wrapper">
            <Shield className="brand-icon" />
          </div>
          <div>
            <div className="brand-title-row">
              <h1 className="brand-title">ZeroAuth Authenticator</h1>
              <span className="badge badge-cyber">RFC 6238 TOTP</span>
            </div>
            <p className="brand-subtitle">
              Zero-Transmission 클라이언트 사이드 암호화 2단계 인증 시스템
            </p>
          </div>
        </div>

        {/* 보안 상태 인디케이터 */}
        <div className="header-status-box">
          <div className="status-item">
            <span className="status-dot active"></span>
            <span className="status-text">Zero-Transmission: 브라우저 내부 연산 (외부 전송 0건)</span>
          </div>
          <div className="status-item">
            <span className="status-dot secure"></span>
            <span className="status-text">CSPRNG: window.crypto.getRandomValues (160-bit)</span>
          </div>
        </div>
      </header>

      {/* ================= TAB NAVIGATION ================= */}
      <nav className="nav-tabs">
        <button
          className={`tab-btn ${activeTab === 'simulator' ? 'active' : ''}`}
          onClick={() => setActiveTab('simulator')}
        >
          <LogIn size={18} />
          <span>실전 로그인 시뮬레이터</span>
          {loginStage === 'dashboard' && <span className="tab-pill-success">인증됨</span>}
        </button>

        <button
          className={`tab-btn ${activeTab === 'setup' ? 'active' : ''}`}
          onClick={() => setActiveTab('setup')}
        >
          <QrCode size={18} />
          <span>2FA 발급 및 실시간 동기화 센터</span>
          <span className="tab-pill-timer">{remainingSeconds}s</span>
        </button>

        <button
          className={`tab-btn ${activeTab === 'security' ? 'active' : ''}`}
          onClick={() => setActiveTab('security')}
        >
          <ShieldCheck size={18} />
          <span>사이버보안 체크포인트 & 무전송 검증</span>
        </button>
      </nav>

      {/* ================= MAIN CONTENT ================= */}
      <main className="main-content">
        {/* ================= TAB 1: 실전 로그인 시뮬레이터 ================= */}
        {activeTab === 'simulator' && (
          <div className="tab-pane">
            {/* 상태 1: 1단계 ID/PW 로그인 폼 */}
            {loginStage === 'credentials' && (
              <div className="simulator-card-wrapper">
                <div className="card login-card">
                  <div className="card-header">
                    <div className="card-badge">Step 1 / 2</div>
                    <h2 className="card-title">기업 포털 보안 로그인</h2>
                    <p className="card-desc">
                      아이디와 비밀번호를 입력한 후 2단계 OTP 인증을 진행합니다.
                    </p>
                  </div>

                  <form onSubmit={handleCredentialsSubmit} className="login-form">
                    <div className="input-group">
                      <label className="input-label" htmlFor="input-username">
                        <User size={16} /> 아이디
                      </label>
                      <input
                        id="input-username"
                        type="text"
                        className="text-input"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        placeholder="아이디를 입력하세요"
                        required
                      />
                    </div>

                    <div className="input-group">
                      <label className="input-label" htmlFor="input-password">
                        <Lock size={16} /> 비밀번호
                      </label>
                      <input
                        id="input-password"
                        type="password"
                        className="text-input"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="비밀번호를 입력하세요"
                        required
                      />
                    </div>

                    <div className="demo-hint-box">
                      <span className="demo-tag">실습 팁</span>
                      <span>
                        스마트폰 Authenticator 앱이 등록되어 있다면 등록된 6자리 번호를 바로 입력할 수 있습니다.
                      </span>
                    </div>

                    <button type="submit" className="btn btn-primary btn-block">
                      <span>다음: 2단계 OTP 인증</span>
                      <ArrowRight size={18} />
                    </button>
                  </form>
                </div>
              </div>
            )}

            {/* 상태 2: 2단계 OTP 모달 / 검증 폼 */}
            {loginStage === '2fa_modal' && (
              <div className="simulator-card-wrapper">
                <div className="card modal-card">
                  <div className="modal-header">
                    <div className="modal-icon-badge">
                      <Smartphone size={28} />
                    </div>
                    <div>
                      <div className="card-badge">Step 2 / 2</div>
                      <h2 className="card-title">2단계 인증 (TOTP 검증)</h2>
                      <p className="card-desc">
                        스마트폰의 <strong>Google Authenticator</strong> 또는 <strong>2FAS</strong> 앱에
                        표시된 6자리 코드를 입력하세요.
                      </p>
                    </div>
                  </div>

                  {/* 6자리 OTP 입력 박스 */}
                  <div className="otp-digit-container">
                    {otpInputs.map((digit, idx) => (
                      <input
                        key={idx}
                        ref={(el) => (otpInputRefs.current[idx] = el)}
                        type="text"
                        inputMode="numeric"
                        maxLength={1}
                        className={`otp-digit-input ${digit ? 'filled' : ''} ${
                          verificationResult?.valid === false ? 'error' : ''
                        }`}
                        value={digit}
                        onChange={(e) => handleOtpChange(idx, e.target.value)}
                        onKeyDown={(e) => handleOtpKeyDown(idx, e)}
                        autoFocus={idx === 0}
                      />
                    ))}
                  </div>

                  {/* 빠른 채우기 & 힌트 */}
                  <div className="quick-actions-row">
                    <button
                      type="button"
                      className="btn-text-action"
                      onClick={handleQuickFill}
                      title="실습 편의를 위해 PC 브라우저에서 계산된 현재 OTP를 자동으로 채웁니다."
                    >
                      <Terminal size={14} /> 현재 발급 코드({activeOtp}) 자동 입력 (빠른 테스트)
                    </button>
                    <span className="clock-drift-notice">
                      <Clock size={13} /> ±1스텝(±30초) 시계 오차 허용 적용
                    </span>
                  </div>

                  {/* 검증 결과 알림 */}
                  {verificationResult && (
                    <div
                      className={`alert-banner ${
                        verificationResult.valid ? 'alert-success' : 'alert-danger'
                      }`}
                    >
                      {verificationResult.valid ? (
                        <>
                          <ShieldCheck size={20} />
                          <div>
                            <strong>인증 성공!</strong>
                            <p>{verificationResult.label}에서 일치 확인되었습니다.</p>
                          </div>
                        </>
                      ) : (
                        <>
                          <ShieldAlert size={20} />
                          <div>
                            <strong>인증 실패</strong>
                            <p>{verificationResult.reason}</p>
                          </div>
                        </>
                      )}
                    </div>
                  )}

                  {/* 액션 버튼 */}
                  <div className="modal-btn-row">
                    <button
                      type="button"
                      className="btn btn-secondary"
                      onClick={() => setLoginStage('credentials')}
                    >
                      이전으로
                    </button>
                    <button
                      type="button"
                      className="btn btn-primary"
                      onClick={executeVerification}
                      disabled={isVerifying || otpInputs.join('').length !== 6}
                    >
                      {isVerifying ? (
                        <>
                          <RefreshCw size={18} className="spin" />
                          <span>검증 중...</span>
                        </>
                      ) : (
                        <>
                          <ShieldCheck size={18} />
                          <span>인증 확인</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* 상태 3: 인증 완료된 관리자 대시보드 */}
            {loginStage === 'dashboard' && sessionData && (
              <div className="dashboard-wrapper">
                <div className="card dashboard-card">
                  <div className="dashboard-header">
                    <div className="success-badge-large">
                      <ShieldCheck size={36} />
                    </div>
                    <div>
                      <h2 className="dashboard-title">보안 관리자 대시보드 인가 완료</h2>
                      <p className="dashboard-subtitle">
                        Zero-Transmission TOTP 2단계 인증이 성공적으로 완료되었습니다.
                      </p>
                    </div>
                    <button className="btn btn-secondary btn-sm" onClick={handleLogout}>
                      <LogOut size={16} /> 로그아웃
                    </button>
                  </div>

                  {/* 인증 세션 메타데이터 */}
                  <div className="session-grid">
                    <div className="session-card">
                      <span className="session-label">인증 계정</span>
                      <strong className="session-val">{sessionData.user}</strong>
                    </div>
                    <div className="session-card">
                      <span className="session-label">인증 시각</span>
                      <strong className="session-val">{sessionData.authenticatedAt}</strong>
                    </div>
                    <div className="session-card">
                      <span className="session-label">시간 동기화 구간</span>
                      <strong className="session-val text-success">{sessionData.matchedWindow}</strong>
                    </div>
                    <div className="session-card">
                      <span className="session-label">네트워크 무전송 검증</span>
                      <strong className="session-val text-cyan">0 Byte 외부 유출 (Web Crypto)</strong>
                    </div>
                  </div>

                  {/* 보안 감사 로그 */}
                  <div className="audit-section">
                    <h3 className="section-title">
                      <Terminal size={18} /> 실시간 보안 감사 이벤트 로그 (Audit Trail)
                    </h3>
                    <div className="audit-log-list">
                      {auditLogs.map((log) => (
                        <div key={log.id} className={`audit-log-item log-${log.status}`}>
                          <span className="log-time">[{log.timestamp}]</span>
                          <span className="log-event">{log.event}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ================= TAB 2: 2FA 발급 및 실시간 동기화 센터 ================= */}
        {activeTab === 'setup' && (
          <div className="tab-pane setup-grid">
            {/* 좌측: 키 발급 및 설정 */}
            <div className="card">
              <div className="card-header">
                <div className="card-header-row">
                  <h2 className="card-title">
                    <Key size={20} /> 1. 비밀 키 발급 및 설정
                  </h2>
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={handleRegenerateKey}
                    title="160비트 암호학적 난수로 새 키 발급"
                  >
                    <RefreshCw size={14} /> 새 보안 키 발급
                  </button>
                </div>
                <p className="card-desc">
                  RFC 4648 Base32 규격의 160-bit(20바이트) 보안 키를 발급합니다.
                </p>
              </div>

              <div className="form-fields">
                <div className="input-group">
                  <label className="input-label">발급자 명 (Issuer)</label>
                  <input
                    type="text"
                    className="text-input"
                    value={issuer}
                    onChange={(e) => setIssuer(e.target.value)}
                    placeholder="ZeroAuth"
                  />
                </div>
                <div className="input-group">
                  <label className="input-label">계정 명 (Account)</label>
                  <input
                    type="text"
                    className="text-input"
                    value={account}
                    onChange={(e) => setAccount(e.target.value)}
                    placeholder="user@k-cybersec.ac.kr"
                  />
                </div>

                {/* Base32 비밀 키 표시 박스 */}
                <div className="secret-display-box">
                  <div className="secret-display-header">
                    <span className="secret-display-label">Base32 Secret Key (160-bit Entropy)</span>
                    <button
                      className="btn-icon-copy"
                      onClick={() => handleCopy(secretKey, setCopiedKey)}
                    >
                      {copiedKey ? <Check size={16} className="text-success" /> : <Copy size={16} />}
                      <span>{copiedKey ? '복사됨!' : '복사'}</span>
                    </button>
                  </div>
                  <div className="secret-key-code">
                    {/* 4글자 단위로 띄어서 가독성 향상 */}
                    {secretKey.match(/.{1,4}/g)?.join(' ') || secretKey}
                  </div>
                  <div className="entropy-meta">
                    <span>엔트로피 풀: 160 bits (20 bytes)</span>
                    <span className="entropy-source">소스: window.crypto.getRandomValues</span>
                  </div>
                </div>
              </div>

              {/* otpauth:// URI */}
              <div className="uri-box">
                <div className="uri-header">
                  <span className="uri-label">RFC 6238 표준 URI (otpauth://)</span>
                  <button
                    className="btn-text-sm"
                    onClick={() => handleCopy(otpauthUri, setCopiedUri)}
                  >
                    {copiedUri ? <Check size={14} className="text-success" /> : <Copy size={14} />}
                    <span>{copiedUri ? '복사됨' : 'URI 복사'}</span>
                  </button>
                </div>
                <code className="uri-code">{otpauthUri}</code>
              </div>
            </div>

            {/* 중앙: QR 코드 연동 */}
            <div className="card qr-card">
              <div className="card-header">
                <h2 className="card-title">
                  <QrCode size={20} /> 2. 스마트폰 QR 코드 스캔
                </h2>
                <p className="card-desc">
                  스마트폰 Authenticator 앱으로 아래 QR 코드를 직접 스캔하세요.
                </p>
              </div>

              <div className="qr-viewport">
                <div className="qr-wrapper">
                  <QRCodeSVG
                    value={otpauthUri}
                    size={200}
                    level="M"
                    includeMargin={true}
                    bgColor="#ffffff"
                    fgColor="#0a0e17"
                  />
                </div>
              </div>

              <div className="qr-guide-box">
                <div className="qr-guide-item">
                  <span className="step-num">1</span>
                  <span>스마트폰의 Google Authenticator 또는 2FAS 앱 실행</span>
                </div>
                <div className="qr-guide-item">
                  <span className="step-num">2</span>
                  <span><strong>+ (추가)</strong> 버튼 클릭 후 <strong>QR 코드 스캔</strong> 선택</span>
                </div>
                <div className="qr-guide-item">
                  <span className="step-num">3</span>
                  <span>스마트폰에 생성된 6자리 번호와 오른쪽 예상 번호 일치 확인</span>
                </div>
              </div>
            </div>

            {/* 우측: 실시간 동기화 모니터 */}
            <div className="card sync-card">
              <div className="card-header">
                <h2 className="card-title">
                  <Clock size={20} /> 3. 실시간 30초 동기화 모니터
                </h2>
                <p className="card-desc">
                  표준 30초 주기 에포크($T = \lfloor Time / 30 \rfloor$)에 따라 자동 갱신됩니다.
                </p>
              </div>

              {/* 카운트다운 타이머 시각화 */}
              <div className="sync-timer-center">
                <div className="circle-timer-wrap">
                  <svg className="timer-svg" width="130" height="130" viewBox="0 0 130 130">
                    <circle
                      className="timer-bg"
                      cx="65"
                      cy="65"
                      r="55"
                      strokeWidth="8"
                      fill="transparent"
                    />
                    <circle
                      className="timer-progress"
                      cx="65"
                      cy="65"
                      r="55"
                      strokeWidth="8"
                      fill="transparent"
                      stroke={timerColor}
                      strokeDasharray={345.57}
                      strokeDashoffset={345.57 - (345.57 * timerPercent) / 100}
                      strokeLinecap="round"
                    />
                  </svg>
                  <div className="timer-text-overlay">
                    <span className="timer-number" style={{ color: timerColor }}>
                      {remainingSeconds}
                    </span>
                    <span className="timer-unit">초 남음</span>
                  </div>
                </div>

                {/* 현재 6자리 OTP 코드 */}
                <div className="active-otp-box">
                  <span className="active-otp-label">현재 유효한 6자리 코드</span>
                  <div className="active-otp-digits">
                    <span className="otp-chunk">{activeOtp.slice(0, 3)}</span>
                    <span className="otp-sep"> </span>
                    <span className="otp-chunk">{activeOtp.slice(3, 6)}</span>
                  </div>
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => handleCopy(activeOtp, setCopiedOtp)}
                  >
                    {copiedOtp ? <Check size={14} className="text-success" /> : <Copy size={14} />}
                    <span>{copiedOtp ? '복사됨' : '번호 복사'}</span>
                  </button>
                </div>
              </div>

              {/* 시계 오차(±1스텝) 코드 미리보기 */}
              <div className="drift-preview-table">
                <div className="drift-row">
                  <span className="drift-label">과거 (T - 1, 직전 30초)</span>
                  <code className="drift-code text-muted">{prevOtp}</code>
                </div>
                <div className="drift-row active-row">
                  <span className="drift-label">현재 (T, 활성 윈도우)</span>
                  <code className="drift-code text-success">{activeOtp}</code>
                </div>
                <div className="drift-row">
                  <span className="drift-label">미래 (T + 1, 다음 30초)</span>
                  <code className="drift-code text-muted">{nextOtp}</code>
                </div>
              </div>

              <div className="sync-footer">
                <button
                  className="btn btn-primary btn-block"
                  onClick={() => {
                    setActiveTab('simulator')
                    setLoginStage('credentials')
                  }}
                >
                  <LogIn size={16} /> 실전 로그인 검증하러 가기
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ================= TAB 3: 보안 아키텍처 및 무전송 검증 ================= */}
        {activeTab === 'security' && (
          <div className="tab-pane security-container">
            <div className="security-hero-card">
              <ShieldCheck size={48} className="text-success" />
              <div>
                <h2>사이버보안 체크포인트 & Zero-Transmission 검증</h2>
                <p>
                  본 어플리케이션은 비밀 키 생성부터 HMAC-SHA1 연산 및 동기화 검증까지 전 과정을 브라우저
                  로컬(Web Crypto API)에서 수행합니다.
                </p>
              </div>
            </div>

            <div className="security-grid">
              {/* 체크포인트 1 */}
              <div className="card">
                <div className="card-header">
                  <div className="checkpoint-badge">체크포인트 1</div>
                  <h3 className="card-title">Math.random() 절대 금지 원칙</h3>
                </div>
                <div className="security-detail">
                  <p>
                    일반적인 <code>Math.random()</code>은 의사 난수 생성기(PRNG)로 과거 시드나 상태를
                    통해 다음 출력값을 예측할 수 있어 암호학적 키 생성에 절대 사용할 수 없습니다.
                  </p>
                  <div className="code-comparison">
                    <div className="code-bad">
                      <span className="code-title">❌ 취약한 방식 (금지)</span>
                      <code>Math.random().toString(36)...</code>
                      <p className="code-desc">예측 가능한 시드, 엔트로피 부족</p>
                    </div>
                    <div className="code-good">
                      <span className="code-title">✅ 구현된 방식 (CSPRNG)</span>
                      <code>window.crypto.getRandomValues(new Uint8Array(20))</code>
                      <p className="code-desc">OS 하드웨어 엔트로피 기반 160비트 암호학적 난수</p>
                    </div>
                  </div>
                </div>
              </div>

              {/* 체크포인트 2 */}
              <div className="card">
                <div className="card-header">
                  <div className="checkpoint-badge">체크포인트 2</div>
                  <h3 className="card-title">Zero-Transmission (무전송 원칙)</h3>
                </div>
                <div className="security-detail">
                  <p>
                    비밀 키와 HMAC-SHA1 서명 연산은 외부 서버나 외부 QR 생성 API(예: Google Charts API)를
                    일절 거치지 않으며, 브라우저 내장 <code>window.crypto.subtle</code>과 클라이언트 SVG
                    엔진으로만 처리됩니다.
                  </p>

                  <div className="verification-steps-box">
                    <h4>🔍 개발자 도구(F12) 직접 검증 가이드</h4>
                    <ol className="verify-list">
                      <li>
                        키보드의 <code>F12</code> 키를 눌러 <strong>개발자 도구</strong>를 엽니다.
                      </li>
                      <li>
                        상단 <strong>Network (네트워크)</strong> 탭을 클릭하고 필터를 <code>Fetch/XHR</code>로
                        설정합니다.
                      </li>
                      <li>
                        '새 보안 키 발급' 버튼을 누르거나 로그인 2FA 검증을 수행합니다.
                      </li>
                      <li>
                        <strong>발생하는 외부 HTTP 네트워크 요청이 0건(Zero Outbound Request)</strong>임을
                        확인합니다.
                      </li>
                    </ol>
                  </div>
                </div>
              </div>
            </div>

            {/* RFC 6238 수학적 원리 정리 카드 */}
            <div className="card rfc-card">
              <div className="card-header">
                <h3 className="card-title">
                  <Terminal size={18} /> RFC 6238 TOTP 수학적 작동 원리
                </h3>
              </div>
              <div className="rfc-content-grid">
                <div className="rfc-step-item">
                  <div className="rfc-step-title">1. 시간 카운터 (Epoch Step)</div>
                  <p>
                    <code>T = Math.floor(UnixTime / 30)</code>
                    <br />
                    30초마다 1씩 증가하는 64비트 정수로 변환하여 8바이트 빅엔디안 버퍼에 기록합니다.
                  </p>
                </div>
                <div className="rfc-step-item">
                  <div className="rfc-step-title">2. HMAC-SHA1 해시 서명</div>
                  <p>
                    <code>HS = HMAC-SHA1(Base32SecretBytes, 8-Byte T)</code>
                    <br />
                    Web Crypto API(crypto.subtle.sign)를 사용해 20바이트 해시 서명을 로컬 계산합니다.
                  </p>
                </div>
                <div className="rfc-step-item">
                  <div className="rfc-step-title">3. 동적 절단 (Dynamic Truncation)</div>
                  <p>
                    <code>Offset = HS[19] & 0x0F</code>
                    <br />
                    마지막 바이트 하위 4비트로 오프셋을 구하고 4바이트 연속 데이터를 추출해 6자리 숫자를
                    도출합니다.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* ================= FOOTER ================= */}
      <footer className="app-footer">
        <p>
          한국폴리텍대학 강서캠퍼스 사이버보안과 실습 프로젝트 &bull; Zero-Transmission TOTP 2FA Service
        </p>
        <p className="footer-sub">
          RFC 6238 &bull; RFC 4226 &bull; Web Crypto API &bull; Zero Outbound Network Payload
        </p>
      </footer>
    </div>
  )
}
