export interface User {
  id: string;
  email: string;
  fullName?: string;
  mobileNumber?: string;
  otpDeliveryPref?: 'email' | 'mobile';
  role: 'user' | 'admin';
  plan: 'pro' | 'free';
  scansThisMonth: number;
  createdAt: string;
}

export interface Breach {
  id: string;
  targetEmail: string;
  Title: string;
  Domain: string;
  BreachDate: string;
  AddedDate: string;
  Description: string;
  DataClasses: string[];
  IsVerified: boolean;
  LogoPath?: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface ScanResult {
  id: string;
  targetEmail: string;
  timestamp: string;
  resultCount: number;
  breaches: Breach[];
  riskScore: number;
  aiSummary?: string;
  scanType?: 'email' | 'link' | 'image';
  targetLink?: string;
  targetImage?: string;
  imageFileName?: string;
  detectedThreats?: string[];
}

export interface PaymentRequest {
  id: string;
  email: string;
  utr: string;
  status: 'pending' | 'approved' | 'rejected';
  planType?: 'weekly' | 'monthly';
  submittedAt: string;
  approvedAt?: string;
}

export interface TerminalLog {
  id: string;
  text: string;
  type: 'command' | 'output' | 'error' | 'success';
  timestamp: string;
}

export interface ThreatIntelligenceAlert {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  description: string;
  impact: string;
  remediation: string;
  timestamp: string;
}

export interface PhishingTactic {
  id: string;
  name: string;
  trendLevel: 'surging' | 'stable' | 'decreasing';
  targetAudience: string;
  description: string;
  redFlags: string[];
  prevention: string;
}

export interface ThreatIntelligenceReport {
  alerts: ThreatIntelligenceAlert[];
  phishingTactics: PhishingTactic[];
  lastUpdated: string;
}

export interface ActivityLog {
  id: string;
  timestamp: string;
  email: string;
  action: string;
  details: string;
  ip: string;
  status: 'success' | 'warning' | 'failed';
}

export interface SystemLog {
  id: string;
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'http';
  category: string;
  message: string;
  metadata?: Record<string, any>;
}

