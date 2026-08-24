-- ==========================================
-- CyberGuard SOC Platform - Supabase Database Schema
-- ==========================================

-- 1. Users Table
CREATE TABLE IF NOT EXISTS public.users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  full_name TEXT,
  mobile_number TEXT,
  otp_delivery_pref TEXT DEFAULT 'email',
  role TEXT DEFAULT 'user',
  plan TEXT DEFAULT 'pro',
  scans_this_month INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for fast user lookup
CREATE INDEX IF NOT EXISTS idx_users_email ON public.users(email);

-- 2. Scans Table
CREATE TABLE IF NOT EXISTS public.scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  target_email TEXT NOT NULL,
  scan_type TEXT DEFAULT 'email',
  timestamp TIMESTAMPTZ DEFAULT NOW(),
  result_count INTEGER DEFAULT 0,
  risk_score INTEGER DEFAULT 0,
  ai_summary TEXT,
  breaches JSONB DEFAULT '[]'::jsonb,
  detected_threats JSONB DEFAULT '[]'::jsonb,
  details JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for scan history lookup by target email
CREATE INDEX IF NOT EXISTS idx_scans_target_email ON public.scans(target_email);

-- 3. Payments Table
CREATE TABLE IF NOT EXISTS public.payments (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  utr TEXT UNIQUE NOT NULL,
  status TEXT DEFAULT 'pending',
  submitted_at TIMESTAMPTZ DEFAULT NOW(),
  approved_at TIMESTAMPTZ
);

-- 4. Activity Logs Table
CREATE TABLE IF NOT EXISTS public.activity_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_email TEXT NOT NULL,
  action TEXT NOT NULL,
  details TEXT,
  ip_address TEXT,
  status TEXT DEFAULT 'info',
  timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- 5. System Logs Table
CREATE TABLE IF NOT EXISTS public.system_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  level TEXT DEFAULT 'info',
  message TEXT NOT NULL,
  meta JSONB DEFAULT '{}'::jsonb,
  timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- Enable Row Level Security (RLS) & Public access policies
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.activity_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow public read users" ON public.users FOR SELECT USING (true);
CREATE POLICY "Allow public insert users" ON public.users FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow public update users" ON public.users FOR UPDATE USING (true);

CREATE POLICY "Allow public read scans" ON public.scans FOR SELECT USING (true);
CREATE POLICY "Allow public insert scans" ON public.scans FOR INSERT WITH CHECK (true);

CREATE POLICY "Allow public read activity_logs" ON public.activity_logs FOR SELECT USING (true);
CREATE POLICY "Allow public insert activity_logs" ON public.activity_logs FOR INSERT WITH CHECK (true);
