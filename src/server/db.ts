import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { User, Breach, ScanResult, PaymentRequest, ActivityLog, SystemLog } from '../types';
import { supabaseServer, isSupabaseConfigured } from './supabase';

const DB_FILE = path.join(process.cwd(), 'db.json');

interface DbSchema {
  users: Record<string, User & { passwordHash: string }>;
  scans: Record<string, ScanResult[]>;
  payments: PaymentRequest[];
  activityLogs?: ActivityLog[];
  systemLogs?: SystemLog[];
}

// Helper for quick SHA256 password hashing
export function hashPassword(password: string): string {
  return crypto.createHash('sha256').update(password).digest('hex');
}

const isProduction = process.env.NODE_ENV === 'production';
const isProdOrSupabase = isSupabaseConfigured || isProduction;

// Initial default state with seeded data for local fallback
const initialDb: DbSchema = isProdOrSupabase
  ? { users: {}, scans: {}, payments: [], activityLogs: [], systemLogs: [] }
  : {
      users: {
        'admin@cyberguard.com': {
          id: 'admin-id',
          email: 'admin@cyberguard.com',
          passwordHash: hashPassword('admin123'),
          role: 'admin',
          plan: 'pro',
          scansThisMonth: 0,
          createdAt: new Date().toISOString(),
        },
        'user@cyberguard.com': {
          id: 'demo-user-id',
          email: 'user@cyberguard.com',
          passwordHash: hashPassword('password123'),
          role: 'user',
          plan: 'pro',
          scansThisMonth: 1,
          createdAt: new Date().toISOString(),
        }
      },
      scans: {
        'user@cyberguard.com': [
          {
            id: 'scan-1',
            targetEmail: 'user@cyberguard.com',
            timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
            resultCount: 2,
            riskScore: 68,
            aiSummary: "Your email user@cyberguard.com was leaked in the Canva and Adobe breaches. Canva leaked passwords and visual assets, whereas Adobe leaked passwords and hints. Immediate password rotation is highly advised.",
            breaches: [
              {
                id: 'canva-breach',
                targetEmail: 'user@cyberguard.com',
                Title: 'Canva',
                Domain: 'canva.com',
                BreachDate: '2019-05-24',
                AddedDate: '2019-05-24T00:00:00Z',
                Description: 'In May 2019, the graphic design tool website Canva suffered a data breach. The attack led to the exposure of data belonging to 137 million users, including email addresses, usernames, real names, and password hashes.',
                DataClasses: ['Email addresses', 'Passwords', 'Names', 'Usernames'],
                IsVerified: true,
                LogoPath: 'https://images.unsplash.com/photo-1611162617213-7d7a39e9b1d7?w=128&auto=format&fit=crop&q=60',
                severity: 'high'
              },
              {
                id: 'adobe-breach',
                targetEmail: 'user@cyberguard.com',
                Title: 'Adobe',
                Domain: 'adobe.com',
                BreachDate: '2013-10-04',
                AddedDate: '2013-10-04T00:00:00Z',
                Description: 'In October 2013, Adobe suffered a massive data breach that exposed customer names, encrypted credit card numbers, and password hints for 38 million active users.',
                DataClasses: ['Email addresses', 'Passwords', 'Password hints', 'Names'],
                IsVerified: true,
                LogoPath: 'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?w=128&auto=format&fit=crop&q=60',
                severity: 'medium'
              }
            ]
          }
        ]
      },
      payments: [
        {
          id: 'pay-demo-1',
          email: 'user@cyberguard.com',
          utr: 'UTR982741938',
          status: 'approved',
          submittedAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(),
          approvedAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000 + 300000).toISOString(),
        }
      ]
    };

// AES-256-CBC database encryption at rest to protect personal details in local JSON storage
const ENCRYPTION_ALGORITHM = 'aes-256-cbc';
const ENCRYPTION_SECRET = process.env.DB_ENCRYPTION_SECRET || (isProduction ? '' : 'cyberguard-soc-default-super-secret-key-32bytes!');

if (isProduction && !process.env.DB_ENCRYPTION_SECRET && !isSupabaseConfigured) {
  throw new Error('FATAL: DB_ENCRYPTION_SECRET environment variable is required in production when Supabase is not configured.');
}

const ENCRYPTION_KEY = crypto.createHash('sha256').update(ENCRYPTION_SECRET || 'fallback-secret-for-key-derive').digest();

export function encryptData(text: string): string {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${encrypted}`;
}

export function decryptData(encryptedText: string): string {
  try {
    const parts = encryptedText.split(':');
    if (parts.length !== 2) {
      return encryptedText;
    }
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    console.error('Database decryption failed. Attempting to parse raw content.', err);
    return encryptedText;
  }
}

class HybridDb {
  private data: DbSchema;

  constructor() {
    this.data = { ...initialDb };
    this.loadLocal();
  }

  private loadLocal() {
    if (isSupabaseConfigured) {
      return;
    }
    try {
      if (fs.existsSync(DB_FILE)) {
        const fileContent = fs.readFileSync(DB_FILE, 'utf8').trim();
        let decryptedContent = fileContent;
        let wasPlain = false;
        if (fileContent.startsWith('{')) {
          decryptedContent = fileContent;
          wasPlain = true;
        } else {
          decryptedContent = decryptData(fileContent);
        }
        this.data = JSON.parse(decryptedContent);
        if (!isProdOrSupabase && initialDb.users['admin@cyberguard.com'] && !this.data.users['admin@cyberguard.com']) {
          this.data.users['admin@cyberguard.com'] = initialDb.users['admin@cyberguard.com'];
        }
        if (wasPlain) {
          this.saveLocal();
        }
      } else {
        this.saveLocal();
      }
    } catch (err) {
      console.warn('Local database loading failed. Running in-memory instead.', err);
    }
  }

  private saveLocal() {
    if (isSupabaseConfigured) {
      return;
    }
    try {
      const jsonString = JSON.stringify(this.data, null, 2);
      const encryptedString = encryptData(jsonString);
      fs.writeFileSync(DB_FILE, encryptedString, 'utf8');
    } catch (err) {
      console.error('Failed to write local database file (swallowed for read-only filesystem compatibility):', err);
    }
  }

  // ----------------------------------------------------------------
  // USER OPERATIONS
  // ----------------------------------------------------------------
  async getUser(email: string): Promise<(User & { passwordHash: string }) | null> {
    const cleanedEmail = email.toLowerCase().trim();

    if (isSupabaseConfigured && supabaseServer) {
      try {
        const { data, error } = await supabaseServer
          .from('users')
          .select('*')
          .eq('email', cleanedEmail)
          .maybeSingle();

        if (!error && data) {
          return {
            id: data.id,
            email: data.email,
            passwordHash: data.password_hash,
            fullName: data.full_name,
            mobileNumber: data.mobile_number,
            otpDeliveryPref: data.otp_delivery_pref,
            role: data.role,
            plan: 'pro',
            scansThisMonth: data.scans_this_month || 0,
            createdAt: data.created_at,
          };
        }
      } catch (err) {
        console.error('[Supabase getUser Error]:', err);
      }
    }

    // Fallback to local storage
    const user = this.data.users[cleanedEmail];
    if (!user) return null;
    return { ...user, plan: 'pro' };
  }

  async createUser(
    email: string,
    passwordHash: string,
    fullName?: string,
    mobileNumber?: string,
    otpDeliveryPref?: 'email' | 'mobile'
  ): Promise<User> {
    const cleanedEmail = email.toLowerCase().trim();
    const id = crypto.randomUUID();
    const createdAt = new Date().toISOString();

    const newUser: User & { passwordHash: string } = {
      id,
      email: cleanedEmail,
      passwordHash,
      fullName,
      mobileNumber,
      otpDeliveryPref,
      role: 'user',
      plan: 'pro',
      scansThisMonth: 0,
      createdAt,
    };

    // Always update local memory/file fallback
    this.data.users[cleanedEmail] = newUser;
    this.saveLocal();

    if (isSupabaseConfigured && supabaseServer) {
      try {
        await supabaseServer.from('users').insert({
          id,
          email: cleanedEmail,
          password_hash: passwordHash,
          full_name: fullName || null,
          mobile_number: mobileNumber || null,
          otp_delivery_pref: otpDeliveryPref || 'email',
          role: 'user',
          plan: 'pro',
          scans_this_month: 0,
          created_at: createdAt,
        });
      } catch (err) {
        console.error('[Supabase createUser Error]:', err);
      }
    }

    const { passwordHash: _, ...userWithoutHash } = newUser;
    return userWithoutHash;
  }

  async updateUser(email: string, updates: Partial<User>): Promise<User | null> {
    const cleanedEmail = email.toLowerCase().trim();

    // Local DB update
    if (this.data.users[cleanedEmail]) {
      this.data.users[cleanedEmail] = {
        ...this.data.users[cleanedEmail],
        ...updates,
        plan: 'pro'
      } as any;
      this.saveLocal();
    }

    if (isSupabaseConfigured && supabaseServer) {
      try {
        const updatePayload: Record<string, any> = {};
        if (updates.fullName !== undefined) updatePayload.full_name = updates.fullName;
        if (updates.mobileNumber !== undefined) updatePayload.mobile_number = updates.mobileNumber;
        if (updates.otpDeliveryPref !== undefined) updatePayload.otp_delivery_pref = updates.otpDeliveryPref;
        if (updates.role !== undefined) updatePayload.role = updates.role;
        if (updates.scansThisMonth !== undefined) updatePayload.scans_this_month = updates.scansThisMonth;

        await supabaseServer
          .from('users')
          .update(updatePayload)
          .eq('email', cleanedEmail);
      } catch (err) {
        console.error('[Supabase updateUser Error]:', err);
      }
    }

    return this.getUser(cleanedEmail);
  }

  async getAllUsers(): Promise<User[]> {
    if (isSupabaseConfigured && supabaseServer) {
      try {
        const { data, error } = await supabaseServer
          .from('users')
          .select('id, email, full_name, mobile_number, otp_delivery_pref, role, plan, scans_this_month, created_at');

        if (!error && data) {
          return data.map((u: any) => ({
            id: u.id,
            email: u.email,
            fullName: u.full_name,
            mobileNumber: u.mobile_number,
            otpDeliveryPref: u.otp_delivery_pref,
            role: u.role,
            plan: 'pro',
            scansThisMonth: u.scans_this_month || 0,
            createdAt: u.created_at,
          }));
        }
      } catch (err) {
        console.error('[Supabase getAllUsers Error]:', err);
      }
    }

    return Object.values(this.data.users).map(({ passwordHash, ...user }) => ({ ...user, plan: 'pro' }));
  }

  // ----------------------------------------------------------------
  // SCAN OPERATIONS
  // ----------------------------------------------------------------
  async getScans(email: string): Promise<ScanResult[]> {
    const cleanedEmail = email.toLowerCase().trim();

    if (isSupabaseConfigured && supabaseServer) {
      try {
        const { data, error } = await supabaseServer
          .from('scans')
          .select('*')
          .eq('user_email', cleanedEmail)
          .order('timestamp', { ascending: false });

        if (!error && data) {
          return data.map((s: any) => ({
            id: s.id,
            targetEmail: s.target_email,
            timestamp: s.timestamp,
            resultCount: s.result_count,
            riskScore: s.risk_score,
            aiSummary: s.ai_summary,
            breaches: typeof s.breaches === 'string' ? JSON.parse(s.breaches) : (s.breaches || []),
          }));
        }
      } catch (err) {
        console.error('[Supabase getScans Error]:', err);
      }
    }

    return this.data.scans[cleanedEmail] || [];
  }

  async addScan(email: string, scan: ScanResult): Promise<void> {
    const cleanedEmail = email.toLowerCase().trim();

    // Local update
    if (!this.data.scans[cleanedEmail]) {
      this.data.scans[cleanedEmail] = [];
    }
    this.data.scans[cleanedEmail].unshift(scan);

    if (this.data.users[cleanedEmail]) {
      this.data.users[cleanedEmail].scansThisMonth += 1;
    }
    this.saveLocal();

    if (isSupabaseConfigured && supabaseServer) {
      try {
        await supabaseServer.from('scans').insert({
          id: scan.id || crypto.randomUUID(),
          user_email: cleanedEmail,
          target_email: scan.targetEmail,
          timestamp: scan.timestamp,
          result_count: scan.resultCount,
          risk_score: scan.riskScore,
          ai_summary: scan.aiSummary,
          breaches: scan.breaches,
        });

        // Increment scans_this_month in Supabase
        const user = await this.getUser(cleanedEmail);
        if (user) {
          await supabaseServer
            .from('users')
            .update({ scans_this_month: (user.scansThisMonth || 0) + 1 })
            .eq('email', cleanedEmail);
        }
      } catch (err) {
        console.error('[Supabase addScan Error]:', err);
      }
    }
  }

  async clearScans(email: string): Promise<void> {
    const cleanedEmail = email.toLowerCase().trim();
    this.data.scans[cleanedEmail] = [];
    this.saveLocal();

    if (isSupabaseConfigured && supabaseServer) {
      try {
        await supabaseServer
          .from('scans')
          .delete()
          .eq('user_email', cleanedEmail);
      } catch (err) {
        console.error('[Supabase clearScans Error]:', err);
      }
    }
  }

  // ----------------------------------------------------------------
  // PAYMENT OPERATIONS
  // ----------------------------------------------------------------
  async getPayments(): Promise<PaymentRequest[]> {
    if (isSupabaseConfigured && supabaseServer) {
      try {
        const { data, error } = await supabaseServer.from('payments').select('*');
        if (!error && data) {
          return data.map((p: any) => ({
            id: p.id,
            email: p.user_email,
            utr: p.utr,
            status: p.status,
            planType: p.plan_type,
            submittedAt: p.submitted_at,
            approvedAt: p.approved_at,
          }));
        }
      } catch (err) {
        console.error('[Supabase getPayments Error]:', err);
      }
    }
    return this.data.payments || [];
  }

  async getPaymentByUtr(utr: string): Promise<PaymentRequest | null> {
    const payments = await this.getPayments();
    return payments.find(p => p.utr.toLowerCase() === utr.trim().toLowerCase()) || null;
  }

  async submitPayment(email: string, utr: string, planType?: 'weekly' | 'monthly'): Promise<PaymentRequest> {
    const cleanedEmail = email.toLowerCase().trim();
    const id = crypto.randomUUID();
    const submittedAt = new Date().toISOString();

    const newPayment: PaymentRequest = {
      id,
      email: cleanedEmail,
      utr: utr.trim(),
      status: 'approved',
      planType: planType || 'monthly',
      submittedAt
    };

    if (!this.data.payments) this.data.payments = [];
    this.data.payments.unshift(newPayment);
    this.saveLocal();

    if (isSupabaseConfigured && supabaseServer) {
      try {
        await supabaseServer.from('payments').insert({
          id,
          user_email: cleanedEmail,
          utr: utr.trim(),
          status: 'approved',
          plan_type: planType || 'monthly',
          submitted_at: submittedAt,
        });
      } catch (err) {
        console.error('[Supabase submitPayment Error]:', err);
      }
    }

    return newPayment;
  }

  // ----------------------------------------------------------------
  // CENTRAL AUDIT & TELEMETRY LOGGING OPERATIONS
  // ----------------------------------------------------------------
  async logUserActivity(
    email: string,
    action: string,
    details: string,
    ip: string = '127.0.0.1',
    status: 'success' | 'warning' | 'failed' = 'success'
  ): Promise<ActivityLog> {
    const cleanedEmail = email.toLowerCase().trim();
    const id = crypto.randomUUID();
    const timestamp = new Date().toISOString();

    const log: ActivityLog = {
      id,
      timestamp,
      email: cleanedEmail,
      action,
      details,
      ip,
      status
    };

    if (!this.data.activityLogs) this.data.activityLogs = [];
    this.data.activityLogs.unshift(log);
    if (this.data.activityLogs.length > 1000) {
      this.data.activityLogs = this.data.activityLogs.slice(0, 1000);
    }
    this.saveLocal();

    if (isSupabaseConfigured && supabaseServer) {
      try {
        await supabaseServer.from('activity_logs').insert({
          id,
          email: cleanedEmail,
          action,
          details,
          ip,
          status,
          timestamp
        });
      } catch (err) {
        console.error('[Supabase logUserActivity Error]:', err);
      }
    }

    return log;
  }

  async logSystemEvent(
    level: 'info' | 'warn' | 'error' | 'http',
    category: string,
    message: string,
    metadata?: Record<string, any>
  ): Promise<SystemLog> {
    const id = crypto.randomUUID();
    const timestamp = new Date().toISOString();

    const log: SystemLog = {
      id,
      timestamp,
      level,
      category,
      message,
      metadata
    };

    if (!this.data.systemLogs) this.data.systemLogs = [];
    this.data.systemLogs.unshift(log);
    if (this.data.systemLogs.length > 2000) {
      this.data.systemLogs = this.data.systemLogs.slice(0, 2000);
    }
    this.saveLocal();

    if (isSupabaseConfigured && supabaseServer) {
      try {
        await supabaseServer.from('system_logs').insert({
          id,
          level,
          category,
          message,
          metadata,
          timestamp
        });
      } catch (err) {
        console.error('[Supabase logSystemEvent Error]:', err);
      }
    }

    return log;
  }

  async getActivityLogs(limit: number = 200): Promise<ActivityLog[]> {
    if (isSupabaseConfigured && supabaseServer) {
      try {
        const { data, error } = await supabaseServer
          .from('activity_logs')
          .select('*')
          .order('timestamp', { ascending: false })
          .limit(limit);

        if (!error && data) {
          return data.map((l: any) => ({
            id: l.id,
            timestamp: l.timestamp,
            email: l.email,
            action: l.action,
            details: l.details,
            ip: l.ip,
            status: l.status,
          }));
        }
      } catch (err) {
        console.error('[Supabase getActivityLogs Error]:', err);
      }
    }

    if (!this.data.activityLogs) return [];
    return this.data.activityLogs.slice(0, limit);
  }

  async getSystemLogs(limit: number = 200): Promise<SystemLog[]> {
    if (isSupabaseConfigured && supabaseServer) {
      try {
        const { data, error } = await supabaseServer
          .from('system_logs')
          .select('*')
          .order('timestamp', { ascending: false })
          .limit(limit);

        if (!error && data) {
          return data.map((l: any) => ({
            id: l.id,
            timestamp: l.timestamp,
            level: l.level,
            category: l.category,
            message: l.message,
            metadata: l.metadata,
          }));
        }
      } catch (err) {
        console.error('[Supabase getSystemLogs Error]:', err);
      }
    }

    if (!this.data.systemLogs) return [];
    return this.data.systemLogs.slice(0, limit);
  }
}

export const db = new HybridDb();
export default db;
