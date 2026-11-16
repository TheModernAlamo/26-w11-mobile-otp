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
  Terminal,
  Sparkles,
  Info
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
  // 활성 뷰: 'dual' (QR 등록 + 실전 로그인 2-in-1), 'security' (보안 아키텍처/무전송 검증)
  const [activeView, setActiveView] = useState('dual')

  // 발급자 및 계정 설정
  const [issuer, setIssuer] = useState('ZeroAuth')
  const [account, setAccount] = useState('user@k-cybersec.ac.kr')
  const [secretKey, setSecretKey] = useState(() => generateBase32Secret(20))

  // 실시간 타이머 및 TOTP 상태
  const [currentStep, setCurrentStep] = useState(() => Math.floor(Date.now() / 1000 / 30))
  const [remainingSeconds, setRemainingSeconds] = useState(() => 30 - (Math.floor(Date.now() / 1000) % 30))
  const [activeOtp, setActiveOtp] = useState('------')
  const [prevOtp, setPrevOtp] = useState('------')
  const [nextOtp, setNextOtp] = useState('------')
  const [copiedKey, setCopiedKey] = useState(false)
  const [copiedOtp, setCopiedOtp] = useState(false)
  const [copiedUri, setCopiedUri] = useState(false)

  // 로그인 시뮬레이터 상태
  // stage: 'credentials' (1단계 ID/PW) | '2fa' (2단계 OTP) | 'dashboard' (인증 성공)
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
      event: '시스템 초기화 완료: Zero-Transmission Web Crypto 활성화',
      status: 'info'
    }
  ])

  // OTP 6자리 인풋 refs
  const otpInputRefs = useRef([])

  // RFC 6238 표준 URI (스마트폰 앱 연동용)
  const otpauthUri = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secretKey}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`

  // 새 비밀 키 발급
  const handleRegenerateKey = useCallback(() => {
    const newKey = generateBase32Secret(20)
    setSecretKey(newKey)
    setVerificationResult(null)
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

  // 타임스텝 또는 비밀 키 변경 시 6자리 OTP 재연산
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

  // 1단계 ID/PW 제출 -> 2단계 모달로 진입
  const handleCredentialsSubmit = (e) => {
    e.preventDefault()
    if (!username.trim() || !password.trim()) {
      alert('아이디와 비밀번호를 입력해주세요.')
      return
    }
    setOtpInputs(['', '', '', '', '', ''])
    setVerificationResult(null)
    setLoginStage('2fa')

    setTimeout(() => {
      otpInputRefs.current[0]?.focus()
    }, 100)
  }

  // 6자리 OTP 입력 처리
  const handleOtpChange = (index, value) => {
    const cleanVal = value.replace(/\D/g, '')
    if (!cleanVal) {
      const newInputs = [...otpInputs]
      newInputs[index] = ''
      setOtpInputs(newInputs)
      return
    }

    // 붙여넣기 등 다중 입력
    if (cleanVal.length > 1) {
      handleOtpPaste(cleanVal)
      return
    }

    const newInputs = [...otpInputs]
    newInputs[index] = cleanVal
    setOtpInputs(newInputs)

    if (index < 5 && cleanVal) {
      otpInputRefs.current[index + 1]?.focus()
    }
  }

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

  // 빠른 채우기 (현재 PC 번호 자동 입력)
  const handleQuickFill = () => {
    if (activeOtp && activeOtp !== '------') {
      const digits = activeOtp.split('')
      setOtpInputs(digits)
      otpInputRefs.current[5]?.focus()
    }
  }

  // 2FA 검증 수행
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

    setTimeout(async () => {
      const result = await verifyTOTPCode(fullCode, secretKey, currentStep)
      setIsVerifying(false)
      setVerificationResult(result)

      if (result.valid) {
        const newSession = {
          user: username,
          authenticatedAt: new Date().toLocaleTimeString(),
          matchedWindow: result.label,
          sessionToken: 'zeroauth_' + Math.random().toString(36).substring(2, 10),
          zeroTransmissionVerified: true
        }
        setSessionData(newSession)

        setAuditLogs((prev) => [
          {
            id: Date.now(),
            timestamp: new Date().toLocaleTimeString(),
            event: `2단계 인증 성공 (${result.label}): 사용자 [${username}] 보안 대시보드 인가`,
            status: 'success'
          },
          ...prev
        ])

        setTimeout(() => {
          setLoginStage('dashboard')
        }, 700)
      } else {
        setAuditLogs((prev) => [
          {
            id: Date.now(),
            timestamp: new Date().toLocaleTimeString(),
            event: `2단계 인증 실패: 입력 코드 [${fullCode}] 불일치 또는 유효 시간 초과`,
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
              <h1 className="brand-title">ZeroAuth Mobile OTP Studio</h1>
              <span className="badge badge-cyber">RFC 6238 TOTP</span>
            </div>
            <p className="brand-subtitle">
              Zero-Transmission 클라이언트 사이드 암호화 2단계 인증 (QR 연동 & 실시간 동기화)
            </p>
          </div>
        </div>

        {/* 상단 보안 상태 표시기 */}
        <div className="header-status-box">
          <div className="status-item">
            <span className="status-dot active"></span>
            <span className="status-text">Zero-Transmission: Web Crypto API 로컬 연산 (네트워크 전송 0건)</span>
          </div>
          <div className="status-item">
            <span className="status-dot secure"></span>
            <span className="status-text">CSPRNG: window.crypto.getRandomValues (160-bit Base32)</span>
          </div>
        </div>
      </header>

      {/* ================= TAB NAVIGATION ================= */}
      <nav className="nav-tabs">
        <button
          className={`tab-btn ${activeView === 'dual' ? 'active' : ''}`}
          onClick={() => setActiveView('dual')}
        >
          <Sparkles size={18} />
          <span>2FA 스튜디오 (QR 연동 + 실전 로그인 2-in-1)</span>
          <span className="tab-pill-timer">{remainingSeconds}s</span>
        </button>

        <button
          className={`tab-btn ${activeView === 'security' ? 'active' : ''}`}
          onClick={() => setActiveView('security')}
        >
          <ShieldCheck size={18} />
          <span>사이버보안 체크포인트 & F12 무전송 검증</span>
        </button>
      </nav>

      {/* ================= MAIN CONTENT ================= */}
      <main className="main-content">
        {activeView === 'dual' && (
          <div className="dual-studio-container">
            {/* ================= 좌측: QR 코드 연동 & 실시간 동기화 센터 ================= */}
            <section className="studio-col qr-sync-panel">
              <div className="card h-full">
                <div className="card-header">
                  <div className="card-badge">QR 코드 연동 및 키 발급 (Criterion 1, 2, 3)</div>
                  <div className="card-header-row">
                    <h2 className="card-title">
                      <QrCode size={22} className="text-cyan" /> 스마트폰 QR 코드 연동 & 실시간 동기화
                    </h2>
                    <button
                      className="btn btn-secondary btn-sm"
                      onClick={handleRegenerateKey}
                      title="160비트 암호학적 난수로 새 키 생성"
                    >
                      <RefreshCw size={14} /> 새 보안 키 발급
                    </button>
                  </div>
                  <p className="card-desc">
                    스마트폰의 Google Authenticator 또는 2FAS 앱으로 아래 QR을 스캔하여 계정을 등록하세요.
                  </p>
                </div>

                {/* QR 코드 표시 영역 (항상 첫 화면에 표시됨!) */}
                <div className="qr-highlight-area">
                  <div className="qr-box-main">
                    <QRCodeSVG
                      value={otpauthUri}
                      size={210}
                      level="M"
                      includeMargin={true}
                      bgColor="#ffffff"
                      fgColor="#0a0e17"
                    />
                  </div>
                  <div className="qr-badge-notice">
                    <Smartphone size={15} />
                    <span>스마트폰 카메라로 즉시 스캔 가능 (otpauth://)</span>
                  </div>
                </div>

                {/* 실시간 30초 동기화 & 실시간 6자리 코드 */}
                <div className="live-sync-widget">
                  <div className="live-sync-header">
                    <div className="sync-title-box">
                      <Clock size={16} className="text-success" />
                      <span className="sync-title">실시간 30초 동기화 모니터</span>
                    </div>
                    <span className="epoch-badge">에포크 T = {currentStep}</span>
                  </div>

                  <div className="sync-display-row">
                    {/* 원형 카운트다운 타이머 */}
                    <div className="circle-timer-wrap-mini">
                      <svg className="timer-svg" width="80" height="80" viewBox="0 0 80 80">
                        <circle
                          className="timer-bg"
                          cx="40"
                          cy="40"
                          r="34"
                          strokeWidth="6"
                          fill="transparent"
                        />
                        <circle
                          className="timer-progress"
                          cx="40"
                          cy="40"
                          r="34"
                          strokeWidth="6"
                          fill="transparent"
                          stroke={timerColor}
                          strokeDasharray={213.63}
                          strokeDashoffset={213.63 - (213.63 * timerPercent) / 100}
                          strokeLinecap="round"
                        />
                      </svg>
                      <div className="timer-text-overlay-mini">
                        <span className="timer-num-mini" style={{ color: timerColor }}>
                          {remainingSeconds}
                        </span>
                        <span className="timer-unit-mini">초</span>
                      </div>
                    </div>

                    {/* 실시간 6자리 예상 OTP 번호 */}
                    <div className="otp-expected-display">
                      <span className="otp-expected-label">스마트폰 앱과 일치하는 실시간 OTP:</span>
                      <div className="otp-expected-digits">
                        <span>{activeOtp.slice(0, 3)}</span>
                        <span className="otp-space"> </span>
                        <span>{activeOtp.slice(3, 6)}</span>
                      </div>
                      <button
                        className="btn-copy-inline"
                        onClick={() => handleCopy(activeOtp, setCopiedOtp)}
                      >
                        {copiedOtp ? <Check size={13} className="text-success" /> : <Copy size={13} />}
                        <span>{copiedOtp ? '복사됨!' : '코드 복사'}</span>
                      </button>
                    </div>
                  </div>

                  {/* 시계 오차(±1스텝) 구간 미리보기 */}
                  <div className="drift-row-strip">
                    <div className="drift-cell">
                      <span className="drift-tag">과거 T-1 (-30s)</span>
                      <code>{prevOtp}</code>
                    </div>
                    <div className="drift-cell active-cell">
                      <span className="drift-tag">현재 T (0s)</span>
                      <code>{activeOtp}</code>
                    </div>
                    <div className="drift-cell">
                      <span className="drift-tag">미래 T+1 (+30s)</span>
                      <code>{nextOtp}</code>
                    </div>
                  </div>
                </div>

                {/* Base32 Secret Key 및 발급자/계정 설정 */}
                <div className="secret-meta-box">
                  <div className="secret-meta-header">
                    <span className="secret-meta-title">
                      <Key size={14} /> Base32 Secret Key (160-bit Entropy)
                    </span>
                    <button
                      className="btn-icon-copy"
                      onClick={() => handleCopy(secretKey, setCopiedKey)}
                    >
                      {copiedKey ? <Check size={14} className="text-success" /> : <Copy size={14} />}
                      <span>{copiedKey ? '복사됨' : '키 복사'}</span>
                    </button>
                  </div>
                  <div className="secret-key-mono">
                    {secretKey.match(/.{1,4}/g)?.join(' ') || secretKey}
                  </div>

                  {/* 발급자 및 계정 수정 입력 */}
                  <div className="issuer-account-inputs">
                    <div className="input-inline">
                      <label>발급자:</label>
                      <input
                        type="text"
                        value={issuer}
                        onChange={(e) => setIssuer(e.target.value)}
                        placeholder="ZeroAuth"
                      />
                    </div>
                    <div className="input-inline">
                      <label>계정:</label>
                      <input
                        type="text"
                        value={account}
                        onChange={(e) => setAccount(e.target.value)}
                        placeholder="user@k-cybersec.ac.kr"
                      />
                    </div>
                  </div>
                </div>

                {/* 표준 URI 복사 박스 */}
                <div className="uri-mini-box">
                  <div className="uri-mini-header">
                    <span>표준 URI (otpauth://)</span>
                    <button
                      className="btn-text-sm"
                      onClick={() => handleCopy(otpauthUri, setCopiedUri)}
                    >
                      {copiedUri ? <Check size={12} className="text-success" /> : <Copy size={12} />}
                      <span>{copiedUri ? '복사됨' : 'URI 복사'}</span>
                    </button>
                  </div>
                  <code className="uri-mini-code">{otpauthUri}</code>
                </div>
              </div>
            </section>

            {/* ================= 우측: 실전 로그인 시뮬레이터 & 검증 ================= */}
            <section className="studio-col simulator-panel">
              {/* 단계 1: 1차 ID/PW 로그인 폼 */}
              {loginStage === 'credentials' && (
                <div className="card h-full">
                  <div className="card-header">
                    <div className="card-badge">실전 서비스 로그인 시뮬레이터 (Step 1 / 2)</div>
                    <h2 className="card-title">
                      <LogIn size={22} className="text-primary" /> 서비스 포털 로그인
                    </h2>
                    <p className="card-desc">
                      아이디와 비밀번호로 1차 로그인한 후, 왼쪽에서 스캔한 2단계 OTP 인증을 진행합니다.
                    </p>
                  </div>

                  <form onSubmit={handleCredentialsSubmit} className="login-form-inner">
                    <div className="input-group">
                      <label className="input-label" htmlFor="input-username">
                        <User size={16} /> 아이디 (Username)
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
                        <Lock size={16} /> 비밀번호 (Password)
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

                    <div className="info-guide-card">
                      <Info size={16} className="text-cyan" />
                      <div>
                        <strong>빠른 테스트 안내:</strong>
                        <p>
                          스마트폰에서 왼쪽 QR 코드를 스캔한 뒤, 바로 아래 버튼을 눌러 2단계 인증 모달로
                          진입하세요.
                        </p>
                      </div>
                    </div>

                    <div className="form-submit-row">
                      <button type="submit" className="btn btn-primary btn-block">
                        <span>로그인 $\rightarrow$ 2단계 OTP 인증 진행</span>
                        <ArrowRight size={18} />
                      </button>
                    </div>
                  </form>
                </div>
              )}

              {/* 단계 2: 2단계 OTP 6자리 검증 모달 */}
              {loginStage === '2fa' && (
                <div className="card h-full modal-glow-card">
                  <div className="card-header">
                    <div className="card-badge text-cyan">2단계 본인 인증 (Step 2 / 2)</div>
                    <h2 className="card-title">
                      <ShieldCheck size={22} className="text-success" /> 2단계 TOTP 인증 코드 검증
                    </h2>
                    <p className="card-desc">
                      스마트폰 Authenticator 앱(또는 왼쪽 화면)에 표시된 6자리 번호를 입력하세요.
                    </p>
                  </div>

                  <div className="otp-verification-body">
                    {/* 6자리 분할 인풋 */}
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

                    {/* 빠른 테스트 자동 채우기 버튼 */}
                    <div className="quick-fill-row">
                      <button
                        type="button"
                        className="btn-quick-fill"
                        onClick={handleQuickFill}
                        title="현재 생성된 6자리 번호를 자동으로 채웁니다."
                      >
                        <Terminal size={14} /> 현재 코드({activeOtp}) 자동 입력 (빠른 테스트)
                      </button>
                      <span className="clock-drift-pill">
                        <Clock size={12} /> $\pm 1$스텝($\pm 30$초) 시계 오차 허용
                      </span>
                    </div>

                    {/* 검증 결과 알림 배너 */}
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
                              <p>{verificationResult.label}에서 코드가 일치했습니다.</p>
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

                    {/* 검증 버튼 */}
                    <div className="verify-actions-row">
                      <button
                        type="button"
                        className="btn btn-secondary"
                        onClick={() => setLoginStage('credentials')}
                      >
                        이전 단계
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

              {/* 단계 3: 인증 완료 대시보드 */}
              {loginStage === 'dashboard' && sessionData && (
                <div className="card h-full dashboard-auth-card">
                  <div className="dashboard-header">
                    <div className="success-badge-large">
                      <ShieldCheck size={36} />
                    </div>
                    <div className="dashboard-header-text">
                      <h2 className="dashboard-title">보안 관리자 대시보드 인가 완료</h2>
                      <p className="dashboard-subtitle">
                        Zero-Transmission TOTP 2단계 인증이 성공적으로 완료되었습니다.
                      </p>
                    </div>
                    <button className="btn btn-secondary btn-sm" onClick={handleLogout}>
                      <LogOut size={16} /> 로그아웃
                    </button>
                  </div>

                  {/* 세션 메타데이터 카드 */}
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

                  {/* 실시간 보안 감사 로그 */}
                  <div className="audit-section">
                    <h3 className="section-title">
                      <Terminal size={17} /> 실시간 보안 감사 이벤트 로그 (Audit Trail)
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
              )}
            </section>
          </div>
        )}

        {/* ================= TAB: 보안 체크포인트 & F12 무전송 검증 ================= */}
        {activeView === 'security' && (
          <div className="tab-pane security-container">
            <div className="security-hero-card">
              <ShieldCheck size={48} className="text-success" />
              <div>
                <h2>사이버보안 체크포인트 & Zero-Transmission 검증 가이드</h2>
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
