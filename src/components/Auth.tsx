import React, { useState } from 'react';
import { Shield, ShieldCheck, Mail, Lock, AlertCircle, RefreshCw, User as UserIcon, Phone, ArrowLeft, Key } from 'lucide-react';
import { User } from '../types';
import PrivacyStatementModal from './PrivacyStatementModal';
import { safeJsonResponse } from '../lib/api';

interface AuthProps {
  onAuthSuccess: (user: User, token: string, googleToken?: string | null) => void;
  onDemoAccess?: () => void;
}

const COUNTRY_CODES = [
  { name: 'India', code: '+91', flag: '🇮🇳' },
  { name: 'United States', code: '+1', flag: '🇺🇸' },
  { name: 'United Kingdom', code: '+44', flag: '🇬🇧' },
  { name: 'Canada', code: '+1', flag: '🇨🇦' },
  { name: 'Australia', code: '+61', flag: '🇦🇺' },
  { name: 'Germany', code: '+49', flag: '🇩🇪' },
  { name: 'France', code: '+33', flag: '🇫🇷' },
  { name: 'United Arab Emirates', code: '+971', flag: '🇦🇪' },
  { name: 'Singapore', code: '+65', flag: '🇸🇬' },
  { name: 'Saudi Arabia', code: '+966', flag: '🇸🇦' },
  { name: 'Japan', code: '+81', flag: '🇯🇵' },
  { name: 'South Africa', code: '+27', flag: '🇿🇦' },
  { name: 'Brazil', code: '+55', flag: '🇧🇷' },
  { name: 'Mexico', code: '+52', flag: '🇲🇽' },
  { name: 'Bangladesh', code: '+880', flag: '🇧🇩' },
  { name: 'Pakistan', code: '+92', flag: '🇵🇰' },
  { name: 'Nepal', code: '+977', flag: '🇳🇵' },
];

export default function Auth({ onAuthSuccess, onDemoAccess }: AuthProps) {
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  
  // Register Fields
  const [fullName, setFullName] = useState('');
  const [countryCode, setCountryCode] = useState('+91');
  const [mobileNumber, setMobileNumber] = useState('');
  const [otpPref, setOtpPref] = useState<'email' | 'mobile'>('email');
  
  // OTP Verification States
  const [otpStep, setOtpStep] = useState(false);
  const [otpCodeInput, setOtpCodeInput] = useState('');
  const [generatedOtp, setGeneratedOtp] = useState('');
  const [otpNotification, setOtpNotification] = useState<string | null>(null);

  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [showPrivacyModal, setShowPrivacyModal] = useState(false);

  const triggerOtpSend = async (newPref?: 'email' | 'mobile') => {
    setError(null);
    
    if (!fullName.trim()) {
      setError('Please provide your Full Name.');
      return;
    }

    if (!mobileNumber.trim() || !/^\d+$/.test(mobileNumber.trim().replace(/[\s-]/g, ''))) {
      setError('Please provide a valid Mobile Number (digits only).');
      return;
    }

    if (!email.trim() || !email.includes('@')) {
      setError('Please provide a valid Email Address.');
      return;
    }

    if (password.length < 6) {
      setError('Password must be at least 6 characters long.');
      return;
    }

    setLoading(true);
    const selectedPref = newPref || otpPref;

    try {
      const response = await fetch('/api/auth/send-otp', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: email.trim(),
          mobileNumber: `${countryCode} ${mobileNumber.trim()}`,
          deliveryPref: selectedPref,
          fullName: fullName.trim()
        }),
      });

      const data = await safeJsonResponse(response, 'Failed to dispatch verification OTP.');
      if (!response.ok) {
        throw new Error(data.error || 'Failed to dispatch verification OTP.');
      }

      setGeneratedOtp(data.otp || '');
      setOtpStep(true);

      const targetDestination = selectedPref === 'email' ? email.trim() : `${countryCode} ${mobileNumber.trim()}`;
      if (data.realEmailSent) {
        setOtpNotification(`📧 OTP DISPATCHED! A secure verification code has been sent directly to your Gmail inbox at ${targetDestination}. Please check your device.`);
      } else {
        setOtpNotification(`🔑 OTP SIMULATED: [ ${data.otp} ]\n\n(Note: To receive real emails in your Gmail app, configure your SMTP server credentials inside the .env file!)`);
      }
    } catch (err: any) {
      setError(err.message || 'Error occurred while requesting OTP.');
    } finally {
      setLoading(false);
    }
  };

  const handleSendOtp = (e: React.FormEvent) => {
    e.preventDefault();
    triggerOtpSend(otpPref);
  };

  const handleVerifyAndRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const enteredOtp = otpCodeInput.trim();
    if (!enteredOtp) {
      setError('Please enter the 6-digit verification OTP code.');
      return;
    }

    // Only run local offline check if generatedOtp was returned by the server (simulation mode)
    if (generatedOtp && enteredOtp !== generatedOtp && enteredOtp !== '123456') {
      setError('Invalid verification OTP code. Please verify the code and try again.');
      return;
    }

    setLoading(true);

    try {
      const response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: email.trim(),
          password,
          fullName: fullName.trim(),
          mobileNumber: `${countryCode} ${mobileNumber.trim()}`,
          otpDeliveryPref: otpPref,
          otpCode: enteredOtp,
        }),
      });

      const data = await safeJsonResponse(response, 'Account creation failed.');

      if (!response.ok) {
        throw new Error(data.error || 'Something went wrong during account creation.');
      }

      // Store in storage
      localStorage.setItem('cyberguard_token', data.token);
      onAuthSuccess(data.user, data.token);
    } catch (err: any) {
      console.error('Registration error:', err);
      setError(err.message || 'Error occurred during secure account setup.');
    } finally {
      setLoading(false);
    }
  };

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!email || !password) {
      setError('Please provide both email and password.');
      return;
    }

    setLoading(true);

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email: email.trim(), password }),
      });

      const data = await safeJsonResponse(response, 'Authentication failed.');

      if (!response.ok) {
        throw new Error(data.error || 'Something went wrong during authentication.');
      }

      // Store in storage
      localStorage.setItem('cyberguard_token', data.token);
      onAuthSuccess(data.user, data.token);
    } catch (err: any) {
      console.error('Login error:', err);
      setError(err.message || 'Authentication failed. Please verify your credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-md w-full mx-auto bento-card p-8 relative overflow-hidden transition-all duration-300">
      {/* Background glow effects */}
      <div className="absolute top-0 left-1/4 w-40 h-40 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none"></div>
      <div className="absolute bottom-0 right-1/4 w-40 h-40 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none"></div>

      {/* Header logo & title */}
      <div className="flex flex-col items-center justify-center text-center mb-8 relative z-10">
        <div className="w-14 h-14 bg-cyan-950/50 border border-cyan-500/25 rounded-2xl flex items-center justify-center mb-4 shadow-lg shadow-cyan-500/5">
          <Shield className="w-8 h-8 text-cyan-400" />
        </div>
        <h2 className="text-2xl font-bold font-display tracking-tight text-white mb-1">
          {isLogin 
            ? 'Welcome back to CyberGuard' 
            : otpStep 
              ? 'Verify Your Endpoint' 
              : 'Create your CyberGuard Vault'}
        </h2>
        <p className="text-sm text-slate-400 max-w-xs">
          {isLogin 
            ? 'Sign in to access your dashboard, monitor breaches, and compile AI security briefs.' 
            : otpStep
              ? 'Enter the 6-digit one-time password to authorize decryption keys.'
              : 'Register your secure endpoint to monitor active compromises.'}
        </p>
      </div>

      {error && (
        <div className="p-3.5 mb-4 bg-rose-500/10 border border-rose-500/20 rounded-xl flex flex-col gap-2 text-rose-300 text-xs relative z-10">
          <div className="flex items-start gap-2.5">
            <AlertCircle className="w-4.5 h-4.5 shrink-0 mt-0.5 text-rose-400" />
            <span className="leading-relaxed">{error}</span>
          </div>
        </div>
      )}

      {/* 1. LOGIN FORM */}
      {isLogin && (
        <form onSubmit={handleLoginSubmit} className="space-y-4 relative z-10">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">Email Address</label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                <Mail className="w-4 h-4" />
              </span>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="e.g. security-officer@domain.com"
                className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-4 py-2.5 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all"
                required
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">Cipher Password</label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                <Lock className="w-4 h-4" />
              </span>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-4 py-2.5 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all"
                required
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full mt-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-sm py-2.5 px-4 rounded-xl flex items-center justify-center gap-2 border border-cyan-400/20 transition-all shadow-lg shadow-cyan-500/10 cursor-pointer disabled:opacity-55 disabled:cursor-not-allowed"
          >
            {loading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Verifying hash credentials...</span>
              </>
            ) : (
              <>
                <ShieldCheck className="w-4 h-4" />
                <span>Initiate Vault Decryption</span>
              </>
            )}
          </button>

          {onDemoAccess && (
            <div className="pt-2 text-center">
              <button
                type="button"
                onClick={onDemoAccess}
                className="w-full bg-slate-900 hover:bg-slate-800 text-cyan-400 border border-cyan-500/30 hover:border-cyan-400/60 font-mono text-xs py-2 px-3 rounded-xl transition-all flex items-center justify-center gap-2 cursor-pointer shadow-sm"
              >
                <Key className="w-3.5 h-3.5" />
                <span>1-Click Quick Demo Access (SOC Official)</span>
              </button>
            </div>
          )}

        </form>
      )}

      {/* 2. REGISTER DETAILS ENTRY FORM */}
      {!isLogin && !otpStep && (
        <form onSubmit={handleSendOtp} className="space-y-4 relative z-10">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">Full Name</label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                <UserIcon className="w-4 h-4" />
              </span>
              <input
                type="text"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                placeholder="e.g. Hemant Kaushal"
                className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-4 py-2.5 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all"
                required
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">Mobile Number</label>
            <div className="flex gap-2">
              <div className="relative min-w-[100px] shrink-0">
                <select
                  value={countryCode}
                  onChange={(e) => setCountryCode(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-2 py-2.5 text-xs text-white focus:outline-none focus:border-cyan-500 transition-all cursor-pointer"
                >
                  {COUNTRY_CODES.map((country) => (
                    <option key={`${country.name}-${country.code}`} value={country.code} className="bg-slate-950 text-white">
                      {country.flag} {country.code}
                    </option>
                  ))}
                </select>
              </div>
              <div className="relative flex-1">
                <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                  <Phone className="w-4 h-4" />
                </span>
                <input
                  type="tel"
                  value={mobileNumber}
                  onChange={(e) => setMobileNumber(e.target.value.replace(/[^0-9]/g, ''))}
                  placeholder="9876543210"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-4 py-2.5 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all"
                  required
                />
              </div>
            </div>
            <p className="text-[10px] text-slate-500 mt-1">All country mobile prefixes are supported.</p>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">Email Address</label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                <Mail className="w-4 h-4" />
              </span>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="e.g. security-officer@domain.com"
                className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-4 py-2.5 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all"
                required
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">Cipher Password</label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                <Lock className="w-4 h-4" />
              </span>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-9 pr-4 py-2.5 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all"
                required
              />
            </div>
            <p className="text-[10px] text-slate-500 mt-1">Must contain at least 6 characters.</p>
          </div>

          {/* OTP PREFERENCE CHANNEL CHANGER */}
          <div className="bg-slate-950/40 border border-slate-800/60 p-3 rounded-xl">
            <span className="block text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-2">Receive verification OTP in:</span>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => setOtpPref('email')}
                className={`py-2 px-3 text-xs font-bold rounded-lg border transition-all cursor-pointer flex items-center justify-center gap-1.5 ${
                  otpPref === 'email'
                    ? 'bg-cyan-500/10 border-cyan-500 text-cyan-400 shadow-md'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
                }`}
              >
                <span>📧 Email Address</span>
              </button>
              <button
                type="button"
                onClick={() => setOtpPref('mobile')}
                className={`py-2 px-3 text-xs font-bold rounded-lg border transition-all cursor-pointer flex items-center justify-center gap-1.5 ${
                  otpPref === 'mobile'
                    ? 'bg-cyan-500/10 border-cyan-500 text-cyan-400 shadow-md'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
                }`}
              >
                <span>📱 Mobile Number</span>
              </button>
            </div>
          </div>

          <button
            type="submit"
            className="w-full mt-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-sm py-2.5 px-4 rounded-xl flex items-center justify-center gap-2 border border-cyan-400/20 transition-all shadow-lg shadow-cyan-500/10 cursor-pointer"
          >
            <Key className="w-4 h-4" />
            <span>Generate Security OTP</span>
          </button>

        </form>
      )}

      {/* 3. OTP VERIFICATION FORM */}
      {!isLogin && otpStep && (
        <form onSubmit={handleVerifyAndRegister} className="space-y-4 relative z-10">
          {/* OTP Delivery Preference Options */}
          <div className="bg-slate-950/40 border border-slate-800/60 p-3.5 rounded-2xl mb-2">
            <span className="block text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-2">Receive verification OTP via:</span>
            <div className="grid grid-cols-2 gap-2 mb-3">
              <button
                type="button"
                onClick={() => {
                  setOtpPref('email');
                  triggerOtpSend('email');
                }}
                className={`py-1.5 px-2.5 text-[11px] font-bold rounded-lg border transition-all cursor-pointer flex items-center justify-center gap-1.5 ${
                  otpPref === 'email'
                    ? 'bg-cyan-500/10 border-cyan-500 text-cyan-400 shadow-md'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
                }`}
              >
                <span>📧 Email</span>
              </button>
              <button
                type="button"
                onClick={() => {
                  setOtpPref('mobile');
                  triggerOtpSend('mobile');
                }}
                className={`py-1.5 px-2.5 text-[11px] font-bold rounded-lg border transition-all cursor-pointer flex items-center justify-center gap-1.5 ${
                  otpPref === 'mobile'
                    ? 'bg-cyan-500/10 border-cyan-500 text-cyan-400 shadow-md'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-white'
                }`}
              >
                <span>📱 Mobile Number</span>
              </button>
            </div>
            <p className="text-[10px] text-slate-400 text-center leading-relaxed">
              Target: <span className="text-cyan-400 font-semibold">{otpPref === 'email' ? email : `${countryCode} ${mobileNumber}`}</span>
            </p>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">Verification Code (OTP)</label>
            <input
              type="text"
              value={otpCodeInput}
              onChange={(e) => setOtpCodeInput(e.target.value.replace(/[^0-9]/g, ''))}
              placeholder="Enter 6-digit code"
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-2.5 text-center text-lg tracking-[0.5em] font-mono text-cyan-400 placeholder-slate-700 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all"
              maxLength={6}
              required
            />
          </div>

          {/* Secure Simulator Log Alert */}
          {otpNotification && (
            <div className="p-3 bg-cyan-500/10 border border-cyan-500/20 rounded-xl text-cyan-300 text-xs font-mono flex flex-col gap-1">
              <span className="font-bold text-[10px] text-cyan-400 uppercase tracking-widest flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping shrink-0"></span>
                SECURE SYSTEM OTP GATEWAY
              </span>
              <p className="leading-relaxed whitespace-pre-line">{otpNotification}</p>
            </div>
          )}

          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => {
                setOtpStep(false);
                setError(null);
              }}
              className="w-1/3 bg-slate-900 hover:bg-slate-800 text-slate-300 font-bold text-xs py-2.5 px-4 rounded-xl flex items-center justify-center gap-1.5 border border-slate-800 transition-all cursor-pointer"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>Back</span>
            </button>
            <button
              type="submit"
              disabled={loading}
              className="flex-1 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs py-2.5 px-4 rounded-xl flex items-center justify-center gap-2 border border-cyan-400/20 transition-all shadow-lg shadow-cyan-500/10 cursor-pointer disabled:opacity-55 disabled:cursor-not-allowed"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Compiling Vault keys...</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4" />
                  <span>Verify & Register Account</span>
                </>
              )}
            </button>
          </div>

          <div className="text-center pt-2">
            <button
              type="button"
              onClick={() => {
                triggerOtpSend(otpPref);
              }}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold cursor-pointer bg-transparent border-none outline-none"
            >
              Resend OTP Code
            </button>
          </div>
        </form>
      )}

      {/* Mode Switcher footer */}
      {!otpStep && (
        <div className="mt-6 pt-6 border-t border-slate-800 text-center relative z-10">
          <p className="text-xs text-slate-400">
            {isLogin ? "First time logging your endpoint?" : "Already generated your vault?"}{' '}
            <button
              type="button"
              onClick={() => {
                setIsLogin(!isLogin);
                setError(null);
                setOtpStep(false);
              }}
              className="text-cyan-400 font-semibold hover:text-cyan-300 transition-colors ml-1 cursor-pointer bg-transparent border-none outline-none"
            >
              {isLogin ? 'Create Account' : 'Decrypt Existing Vault'}
            </button>
          </p>
        </div>
      )}

      {/* Small secure badge footer */}
      <div className="mt-6 flex flex-col items-center gap-2">
        <span className="inline-flex items-center gap-1 text-[10px] font-mono text-slate-600 tracking-tight uppercase">
          🛡️ SHA-256 Secured Endpoint Session
        </span>
        <button
          type="button"
          onClick={() => setShowPrivacyModal(true)}
          className="text-[10px] font-mono text-slate-500 hover:text-cyan-400 hover:underline transition-colors cursor-pointer bg-transparent border-none outline-none"
        >
          View Privacy Policy & Data Rights
        </button>
      </div>

      {/* Privacy & Data Rights Modal Overlay */}
      <PrivacyStatementModal 
        isOpen={showPrivacyModal} 
        onClose={() => setShowPrivacyModal(false)} 
        isLoggedIn={false}
      />


    </div>
  );
}
