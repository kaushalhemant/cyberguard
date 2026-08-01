import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { User, Breach, ScanResult, PaymentRequest, ActivityLog, SystemLog } from '../types';

const DB_FILE = path.join(process.cwd(), 'db.json');

interface DbSchema {
  users: Record<string, User & { passwordHash: string }>;
  scans: Record<string, ScanResult[]>;
  payments: PaymentRequest[];
  activityLogs?: ActivityLog[];
  systemLogs?: SystemLog[];
}

// Initial default state with seeded data
const initialDb: DbSchema = {
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
      plan: 'free',
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

// Helper for quick SHA256 password hashing
export function hashPassword(password: string): string {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// AES-256-CBC database encryption at rest to protect personal details
const ENCRYPTION_ALGORITHM = 'aes-256-cbc';
const ENCRYPTION_SECRET = process.env.DB_ENCRYPTION_SECRET || 'cyberguard-soc-default-super-secret-key-32bytes!';
const ENCRYPTION_KEY = crypto.createHash('sha256').update(ENCRYPTION_SECRET).digest();

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
      // Not encrypted format (starts with standard JSON or corrupted), return as-is for migration
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

class JsonDb {
  private data: DbSchema;

  constructor() {
    this.data = { ...initialDb };
    this.load();
  }

  private load() {
    try {
      if (fs.existsSync(DB_FILE)) {
        const fileContent = fs.readFileSync(DB_FILE, 'utf8').trim();
        let decryptedContent = fileContent;
        let wasPlain = false;
        // If it starts with '{', it's unencrypted JSON, otherwise it's encrypted
        if (fileContent.startsWith('{')) {
          decryptedContent = fileContent;
          wasPlain = true;
        } else {
          decryptedContent = decryptData(fileContent);
        }
        this.data = JSON.parse(decryptedContent);
        // Ensure admin always exists in loaded file too
        if (!this.data.users['admin@cyberguard.com']) {
          this.data.users['admin@cyberguard.com'] = initialDb.users['admin@cyberguard.com'];
        }
        if (wasPlain) {
          this.save(); // Upgrade database to AES-256 encrypted-at-rest immediately
        }
      } else {
        this.save();
      }
    } catch (err) {
      console.warn('Database loading failed. Running in-memory instead.', err);
    }
  }

  private save() {
    try {
      const jsonString = JSON.stringify(this.data, null, 2);
      const encryptedString = encryptData(jsonString);
      fs.writeFileSync(DB_FILE, encryptedString, 'utf8');
    } catch (err) {
      console.error('Failed to write database file:', err);
    }
  }

  // User Operations
  getUser(email: string) {
    const cleanedEmail = email.toLowerCase().trim();
    const user = this.data.users[cleanedEmail];
    if (!user) return null;
    user.plan = 'pro';
    return user;
  }

  createUser(email: string, passwordHash: string, fullName?: string, mobileNumber?: string, otpDeliveryPref?: 'email' | 'mobile'): User {
    const cleanedEmail = email.toLowerCase().trim();
    const newUser: User & { passwordHash: string } = {
      id: crypto.randomUUID(),
      email: cleanedEmail,
      passwordHash,
      fullName,
      mobileNumber,
      otpDeliveryPref,
      role: 'user',
      plan: 'pro',
      scansThisMonth: 0,
      createdAt: new Date().toISOString(),
    };
    this.data.users[cleanedEmail] = newUser;
    this.save();
    
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { passwordHash: _, ...userWithoutHash } = newUser;
    return userWithoutHash;
  }

  updateUser(email: string, updates: Partial<User>) {
    const cleanedEmail = email.toLowerCase().trim();
    if (this.data.users[cleanedEmail]) {
      this.data.users[cleanedEmail] = {
        ...this.data.users[cleanedEmail],
        ...updates,
        plan: 'pro'
      } as any;
      this.save();
      return this.data.users[cleanedEmail];
    }
    return null;
  }

  getAllUsers(): User[] {
    return Object.values(this.data.users).map(({ passwordHash, ...user }) => ({ ...user, plan: 'pro' }));
  }

  // Scan Operations
  getScans(email: string): ScanResult[] {
    return this.data.scans[email.toLowerCase().trim()] || [];
  }

  addScan(email: string, scan: ScanResult) {
    const cleanedEmail = email.toLowerCase().trim();
    if (!this.data.scans[cleanedEmail]) {
      this.data.scans[cleanedEmail] = [];
    }
    this.data.scans[cleanedEmail].unshift(scan);
    
    // Increment scans for the user
    if (this.data.users[cleanedEmail]) {
      this.data.users[cleanedEmail].scansThisMonth += 1;
    }
    
    this.save();
  }

  clearScans(email: string) {
    const cleanedEmail = email.toLowerCase().trim();
    this.data.scans[cleanedEmail] = [];
    this.save();
  }

  // Payment Operations (Deprecating - All users have free Pro access)
  getPayments(): PaymentRequest[] {
    return this.data.payments || [];
  }

  getPaymentByUtr(utr: string): PaymentRequest | null {
    return null;
  }

  getPendingPaymentForUser(email: string): PaymentRequest | null {
    return null;
  }

  submitPayment(email: string, utr: string, planType?: 'weekly' | 'monthly'): PaymentRequest {
    const cleanedEmail = email.toLowerCase().trim();
    const newPayment: PaymentRequest = {
      id: crypto.randomUUID(),
      email: cleanedEmail,
      utr: utr.trim(),
      status: 'approved',
      planType: planType || 'monthly',
      submittedAt: new Date().toISOString()
    };
    return newPayment;
  }

  approvePayment(paymentId: string): PaymentRequest | null {
    return null;
  }

  rejectPayment(paymentId: string): PaymentRequest | null {
    return null;
  }

  // Central Audit & Telemetry Logging Operations
  logUserActivity(email: string, action: string, details: string, ip: string = '127.0.0.1', status: 'success' | 'warning' | 'failed' = 'success'): ActivityLog {
    if (!this.data.activityLogs) this.data.activityLogs = [];
    const log: ActivityLog = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      email: email.toLowerCase().trim(),
      action,
      details,
      ip,
      status
    };
    this.data.activityLogs.unshift(log);
    if (this.data.activityLogs.length > 1000) {
      this.data.activityLogs = this.data.activityLogs.slice(0, 1000);
    }
    this.save();
    return log;
  }

  logSystemEvent(level: 'info' | 'warn' | 'error' | 'http', category: string, message: string, metadata?: Record<string, any>): SystemLog {
    if (!this.data.systemLogs) this.data.systemLogs = [];
    const log: SystemLog = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      level,
      category,
      message,
      metadata
    };
    this.data.systemLogs.unshift(log);
    if (this.data.systemLogs.length > 2000) {
      this.data.systemLogs = this.data.systemLogs.slice(0, 2000);
    }
    this.save();
    return log;
  }

  getActivityLogs(limit: number = 200): ActivityLog[] {
    if (!this.data.activityLogs) return [];
    return this.data.activityLogs.slice(0, limit);
  }

  getSystemLogs(limit: number = 200): SystemLog[] {
    if (!this.data.systemLogs) return [];
    return this.data.systemLogs.slice(0, limit);
  }
}

export const db = new JsonDb();
export default db;
