-- =================================================================
-- CyberGuard SOC - Supabase PostgreSQL Database Schema
-- =================================================================

-- 1. Enable UUID Extension if required
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 2. USERS TABLE
CREATE TABLE IF NOT EXISTS public.users (
  id TEXT PRIMARY KEY DEFAULT uuid_generate_v4()::text,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  full_name TEXT,
  mobile_number TEXT,
  otp_delivery_pref TEXT DEFAULT 'email',
  role TEXT NOT NULL DEFAULT 'user',
  plan TEXT NOT NULL DEFAULT 'pro',
  scans_this_month INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. SCANS TABLE
CREATE TABLE IF NOT EXISTS public.scans (
  id TEXT PRIMARY KEY DEFAULT uuid_generate_v4()::text,
  user_email TEXT NOT NULL,
  target_email TEXT NOT NULL,
  timestamp TIMESTAMPTZ DEFAULT NOW(),
  result_count INTEGER DEFAULT 0,
  risk_score INTEGER DEFAULT 0,
  ai_summary TEXT,
  breaches JSONB DEFAULT '[]'::jsonb,
  scan_type TEXT DEFAULT 'email',
  target_link TEXT,
  target_image TEXT,
  image_file_name TEXT,
  detected_threats JSONB DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_scans_user_email ON public.scans(user_email);

-- 4. PAYMENTS TABLE
CREATE TABLE IF NOT EXISTS public.payments (
  id TEXT PRIMARY KEY DEFAULT uuid_generate_v4()::text,
  user_email TEXT NOT NULL,
  utr TEXT NOT NULL,
  status TEXT DEFAULT 'approved',
  plan_type TEXT DEFAULT 'monthly',
  submitted_at TIMESTAMPTZ DEFAULT NOW(),
  approved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_payments_user_email ON public.payments(user_email);

-- 5. ACTIVITY LOGS TABLE (AUDIT TRAIL)
CREATE TABLE IF NOT EXISTS public.activity_logs (
  id TEXT PRIMARY KEY DEFAULT uuid_generate_v4()::text,
  email TEXT NOT NULL,
  action TEXT NOT NULL,
  details TEXT,
  ip TEXT DEFAULT '127.0.0.1',
  status TEXT DEFAULT 'success',
  timestamp TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_activity_logs_email ON public.activity_logs(email);

-- 6. SYSTEM LOGS TABLE (TELEMETRY)
CREATE TABLE IF NOT EXISTS public.system_logs (
  id TEXT PRIMARY KEY DEFAULT uuid_generate_v4()::text,
  level TEXT NOT NULL,
  category TEXT NOT NULL,
  message TEXT NOT NULL,
  metadata JSONB,
  timestamp TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_system_logs_timestamp ON public.system_logs(timestamp DESC);

-- 7. ROW LEVEL SECURITY (RLS) POLICIES
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.activity_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.system_logs ENABLE ROW LEVEL SECURITY;

-- Allow service role full access (Backend Node.js API server operates with service role / secret)
CREATE POLICY "Service Role Full Access Users" ON public.users FOR ALL USING (true);
CREATE POLICY "Service Role Full Access Scans" ON public.scans FOR ALL USING (true);
CREATE POLICY "Service Role Full Access Payments" ON public.payments FOR ALL USING (true);
CREATE POLICY "Service Role Full Access Activity Logs" ON public.activity_logs FOR ALL USING (true);
CREATE POLICY "Service Role Full Access System Logs" ON public.system_logs FOR ALL USING (true);

-- 8. INITIAL SEED DATA
INSERT INTO public.users (id, email, password_hash, role, plan, scans_this_month, created_at)
VALUES 
  ('admin-id', 'admin@cyberguard.com', '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', 'admin', 'pro', 0, NOW()),
  ('demo-user-id', 'user@cyberguard.com', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'user', 'pro', 1, NOW())
ON CONFLICT (email) DO NOTHING;
