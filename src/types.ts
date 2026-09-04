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
  targetEmail?: string;
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
  forensicSummary?: string;
  aiSummary?: string; // Legacy compatibility alias
  scoreBreakdown?: { rule: string; points: number }[];
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

export interface OsintResult {
  target: string;
  resolvedIp: string;
  hostname: string;
  location: {
    country: string;
    city: string;
    isp: string;
    asn: string;
    flag: string;
  };
  reputationScore: number; // 0 (Clean) to 100 (Malicious)
  blacklists: { name: string; listed: boolean; category?: string }[];
  openPorts: { port: number; service: string; state: 'open' | 'filtered' | 'closed'; risk: 'high' | 'medium' | 'low' }[];
  dnsRecords: { type: string; value: string; status: 'ok' | 'warning' | 'missing' }[];
  sslCert?: {
    valid: boolean;
    issuer: string;
    expiresInDays: number;
    cipher: string;
    sanDomains: string[];
  };
  threatCategories: string[];
  investigatorNotes?: string;
  scoreBreakdown?: { rule: string; points: number }[];
  timestamp: string;
}

export interface HashAnalysisResult {
  hash: string;
  hashType: 'MD5' | 'SHA1' | 'SHA256' | 'SHA-1' | 'SHA-256' | 'UNKNOWN';
  fileName?: string;
  fileSizeBytes?: number;
  detectedFormat: string;
  magicBytes: string;
  entropyScore: number; // 0 to 8
  isPackedOrEncrypted: boolean;
  malwareClassification: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  threatFamily?: string;
  matchedYaraRules: string[];
  threatIndicators: string[];
  recommendation: string;
  scoreBreakdown?: { rule: string; points: number }[];
  timestamp: string;
}

export interface SocIncident {
  id: string;
  title: string;
  target: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'new' | 'investigating' | 'mitigated' | 'escalated' | 'false_positive';
  category: 'Phishing' | 'Ransomware' | 'Zero-Day' | 'Credential Abuse' | 'DDoS' | 'Malware Payload';
  mitreTactic: string;
  mitreTechniqueId: string;
  description: string;
  affectedAsset: string;
  assignedOfficer: string;
  containmentActionTaken?: string;
  notes: string[];
  timestamp: string;
}

export interface CveRecord {
  id: string;
  sourceIdentifier: string;
  published: string;
  lastModified: string;
  vulnStatus: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  score: number;
  vectorString?: string;
}

// =====================================================================
// 2030 NEXT-GEN CYBERSECURITY & DEFENSE TYPES
// =====================================================================

export interface PqcCipherAudit {
  name: string;
  algorithmType: 'KEM' | 'Signature' | 'Hybrid' | 'Classical';
  nistStandard: 'FIPS 203 (ML-KEM)' | 'FIPS 204 (ML-DSA)' | 'FIPS 205 (SLH-DSA)' | 'Non-Compliant Classical (RSA/ECC)' | 'Draft PQC';
  securityLevel: 1 | 3 | 5 | 0; // NIST Security Levels 1-5 (0 = broken by Shor's algorithm)
  quantumResistant: boolean;
  keySizeBits: number;
  shorVulnerability: 'Critical (Broken in <10s)' | 'High' | 'Immune (Lattice Hardness)' | 'Immune (Hash Hardness)';
}

export interface PqcAnalysisResult {
  target: string;
  quantumReadinessScore: number; // 0 (Legacy/Compromised) to 100 (Full PQC Mesh)
  complianceStatus: 'Fully PQC Compliant (2030 Standards)' | 'Hybrid PQC Transit' | 'Critical Q-Day Exposure';
  hndlRisk: 'Severe (Data Vulnerable to Harvest-Now-Decrypt-Later)' | 'Moderate' | 'Protected';
  detectedCipherSuite: string;
  kemAlgorithm: string;
  signatureAlgorithm: string;
  ciphers: PqcCipherAudit[];
  quantumMigrationRoadmap: string[];
  qkdCompatibility: boolean;
  scoreBreakdown: { rule: string; points: number; status: 'pass' | 'fail' | 'warn' }[];
  timestamp: string;
}

export interface QuantumSimResult {
  cipher: string;
  keySize: number;
  estimatedLogicalQubits: number;
  shorExecutionSeconds: number;
  classicalCrackingYears: string;
  latticeHardnessDimension: number;
  quantumResistanceScore: number; // 0 to 100
  securityAssessment: string;
  recommendedPqcAlternative: string;
}

export interface AiAgent {
  id: string;
  name: string;
  codename: string;
  role: 'Zero-Day Interception' | 'Quantum Lattice Audit' | 'Adversarial AI & Deepfake Hunter' | 'Autonomous Counter-Payload';
  status: 'ACTIVE' | 'NEUTRALIZING' | 'PATROLLING' | 'CONSENSUS_VOTING';
  confidenceScore: number;
  threatsNeutralized: number;
  activePlaybook: string;
  latencyMs: number;
}

export interface AiSwarmEvent {
  id: string;
  timestamp: string;
  agentCodename: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  eventType: 'ZERO_DAY_PREEMPTION' | 'LATTICE_INTEGRITY_CHECK' | 'DEEPFAKE_NEUTRALIZATION' | 'MICRO_ISOLATION' | 'ADVERSARIAL_LLM_PROBE';
  target: string;
  autonomousAction: string;
  consensusScore: number;
  details: string;
}

export interface DeepfakeForensicsResult {
  targetName: string;
  mediaType: 'image' | 'audio' | 'video' | 'synthetic_identity';
  syntheticConfidence: number; // 0 (100% Authentic) to 100 (100% Generative Synthetic)
  classification: 'AUTHENTIC_ORIGINAL' | 'SUSPICIOUS_HYBRID' | 'SYNTHETIC_DEEPFAKE' | 'VOICE_CLONE_INJECTION';
  spectralAnomalyScore: number; // FFT frequency phase distortion
  rppgPulseDetected: boolean; // Remote Photoplethysmography micro-blood flow
  rppgConfidence: number;
  voiceJitterVariance?: number;
  detectedGenerativeArchetype: string; // e.g., 'Diffusion Latent Warp v8', 'Neural Voice Formant Synth'
  redFlags: string[];
  forensicEvidence: { metric: string; measured: string; baseline: string; status: 'clean' | 'anomaly' }[];
  mitreAtlasTechnique: string;
  timestamp: string;
}

export interface LeoSatelliteNode {
  id: string;
  name: string;
  constellation: 'STARLINK-GEN3' | 'KUIPER-MESH' | 'ONEWEB-DEFENSE' | 'QUANTUM-RELAY-1';
  altitudeKm: number;
  orbitInclination: string;
  qkdStatus: 'ACTIVE_ENTANGLED' | 'SYNCING' | 'RE-KEYING';
  photonRateQps: number; // Quantum Photons per second
  linkLatencyMs: number;
  securityState: 'SECURE_MESH' | 'ANOMALOUS_JAMMING' | 'PQC_ENCLAVE_LOCKED';
  activeGroundStation: string;
}

export interface SatelliteMeshTelemetry {
  constellationHealthScore: number;
  activeNodes: LeoSatelliteNode[];
  totalPhotonThroughput: string;
  spaceToGroundQkdLock: boolean;
  interSatelliteLatticeLinks: number;
  zeroTrustAttestation: 'FIPS 140-3 L4 Hardware Enclave' | 'Attested';
  timestamp: string;
}



