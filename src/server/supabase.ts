import { createClient, SupabaseClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

dotenv.config();

function getEnvVar(key: string): string {
  const val = process.env[key];
  if (!val) return '';
  return val.replace(/^["']|["']$/g, '').trim();
}

const supabaseUrl = getEnvVar('SUPABASE_URL') || getEnvVar('VITE_SUPABASE_URL');
const supabaseKey = getEnvVar('SUPABASE_SECRET_KEY') || getEnvVar('SUPABASE_SERVICE_ROLE_KEY') || getEnvVar('SUPABASE_PUBLISHABLE_KEY') || getEnvVar('SUPABASE_ANON_KEY') || getEnvVar('VITE_SUPABASE_PUBLISHABLE_KEY') || getEnvVar('VITE_SUPABASE_ANON_KEY');

export const isSupabaseConfigured = Boolean(supabaseUrl && supabaseKey);

let supabaseServerClient: SupabaseClient | null = null;

if (isSupabaseConfigured) {
  try {
    supabaseServerClient = createClient(supabaseUrl, supabaseKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      },
    });
    console.log('[CyberGuard Supabase] Initialized Supabase client successfully.');
  } catch (err) {
    console.error('[CyberGuard Supabase] Error initializing client:', err);
    supabaseServerClient = null;
  }
} else {
  console.log('[CyberGuard Supabase] Supabase credentials not set in environment. Running with local storage fallback.');
}

export const supabaseServer = supabaseServerClient;
export default supabaseServer;
