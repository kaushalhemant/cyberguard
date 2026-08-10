import dotenv from 'dotenv';
dotenv.config();

import { generateBreachReportSummary, generateLinkThreatReport, generateImageThreatReport, performSearchGrounding, performGeminiIntelligence, generateGmailMessageThreatReport } from '../src/server/cyberguardAI';
import { scanUrl, scanEmail, scanImage, scanUnified } from '../src/server/scanners/unifiedScanner';
import { db } from '../src/server/db';

async function testEverything() {
  console.log("=========================================");
  console.log("RUNNING COMPREHENSIVE CYBERGUARD AUDIT...");
  console.log("=========================================\n");

  // 1. Test Email Scan & AI Breach Summary
  try {
    console.log("[TEST 1] generateBreachReportSummary...");
    const breachReport = await generateBreachReportSummary('testuser@gmail.com', [
      {
        id: 'b1',
        Title: 'Test Breach',
        Domain: 'test.com',
        BreachDate: '2023-01-01',
        AddedDate: '2023-01-01T00:00:00Z',
        Description: 'Test leak',
        DataClasses: ['Passwords', 'Email addresses'],
        IsVerified: true,
        LogoPath: '',
        severity: 'high',
        targetEmail: 'testuser@gmail.com'
      }
    ], 50);
    console.log("Breach Report Output Length:", breachReport.length);
    console.log("Breach Report Snippet:", breachReport.substring(0, 150), "...\n");
  } catch (err: any) {
    console.error("❌ TEST 1 FAILED:", err);
  }

  // 2. Test Link Threat Report
  try {
    console.log("[TEST 2] generateLinkThreatReport...");
    const linkReport = await generateLinkThreatReport('https://paypa1-verify-login.xyz/auth');
    console.log("Link Report Risk Score:", linkReport.riskScore);
    console.log("Link Report Threats:", linkReport.threats);
    console.log("Link Report Summary Snippet:", linkReport.aiSummary.substring(0, 150), "...\n");
  } catch (err: any) {
    console.error("❌ TEST 2 FAILED:", err);
  }

  // 3. Test Image Threat Report
  try {
    console.log("[TEST 3] generateImageThreatReport...");
    const dummyBase64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
    const imgReport = await generateImageThreatReport(dummyBase64, 'image/png', 'suspicious_invoice.png');
    console.log("Image Report Risk Score:", imgReport.riskScore);
    console.log("Image Report Threats:", imgReport.threats);
    console.log("Image Report Summary Snippet:", imgReport.aiSummary.substring(0, 150), "...\n");
  } catch (err: any) {
    console.error("❌ TEST 3 FAILED:", err);
  }

  // 4. Test Search Grounding
  try {
    console.log("[TEST 4] performSearchGrounding...");
    const sgReport = await performSearchGrounding('phishing mitigation strategies');
    console.log("Search Grounding Text Length:", sgReport.text.length);
    console.log("Sources Count:", sgReport.sources.length);
    console.log("Search Grounding Snippet:", sgReport.text.substring(0, 150), "...\n");
  } catch (err: any) {
    console.error("❌ TEST 4 FAILED:", err);
  }

  // 5. Test Gemini Intelligence
  try {
    console.log("[TEST 5] performGeminiIntelligence...");
    const intelReport = await performGeminiIntelligence('How to secure active directory', 'complex');
    console.log("Intelligence Output Length:", intelReport.length);
    console.log("Intelligence Snippet:", intelReport.substring(0, 150), "...\n");
  } catch (err: any) {
    console.error("❌ TEST 5 FAILED:", err);
  }

  // 6. Test Modular URL Scanner
  try {
    console.log("[TEST 6] scanUrl (Modular URL Scanner)...");
    const modUrlRes = await scanUrl('https://paypa1-security-update.xyz/login');
    console.log("Modular URL Risk Score:", modUrlRes.riskScore, "Level:", modUrlRes.riskLevel);
    console.log("Triggered Flags Count:", modUrlRes.triggeredFlags.length);
    modUrlRes.triggeredFlags.forEach(f => console.log(`  - ${f.name} (weight: ${f.weight})`));
    console.log();
  } catch (err: any) {
    console.error("❌ TEST 6 FAILED:", err);
  }

  // 7. Test Modular Email Scanner
  try {
    console.log("[TEST 7] scanEmail (Modular Email Scanner)...");
    const rawEmailSample = `From: support@paypa1-verify.com
To: victim@example.com
Subject: Urgent: Account Suspended within 24 hours!
Date: Mon, 10 Aug 2026 12:00:00 +0000

Dear customer, your account has been suspended due to unauthorized login attempts.
Please verify your identity immediately at http://paypa1-verify.com/login before 24 hours pass.
`;
    const modEmailRes = await scanEmail(rawEmailSample);
    console.log("Modular Email Risk Score:", modEmailRes.riskScore, "Level:", modEmailRes.riskLevel);
    console.log("Triggered Flags Count:", modEmailRes.triggeredFlags.length);
    modEmailRes.triggeredFlags.forEach(f => console.log(`  - ${f.name} (weight: ${f.weight})`));
    console.log();
  } catch (err: any) {
    console.error("❌ TEST 7 FAILED:", err);
  }

  // 8. Test Modular Image Scanner
  try {
    console.log("[TEST 8] scanImage (Modular Image Scanner)...");
    const dummyBuffer = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==", "base64");
    const modImgRes = await scanImage(dummyBuffer, 'crypto_wallet_seed_phishing.png', 'image/png');
    console.log("Modular Image Risk Score:", modImgRes.riskScore, "Level:", modImgRes.riskLevel);
    console.log("Triggered Flags Count:", modImgRes.triggeredFlags.length);
    modImgRes.triggeredFlags.forEach(f => console.log(`  - ${f.name} (weight: ${f.weight})`));
    console.log();
  } catch (err: any) {
    console.error("❌ TEST 8 FAILED:", err);
  }

  // 9. Test Modular Unified Scanner
  try {
    console.log("[TEST 9] scanUnified (Modular Unified Scanner)...");
    const modUnifiedRes = await scanUnified({
      url: 'https://paypa1-security.xyz',
      email: 'From: support@paypa1-security.xyz\nSubject: Urgent account verification\n\nVerify at https://paypa1-security.xyz'
    });
    console.log("Unified Risk Score:", modUnifiedRes.riskScore, "Level:", modUnifiedRes.riskLevel);
    console.log("Triggered Flags Count:", modUnifiedRes.triggeredFlags.length, "\n");
  } catch (err: any) {
    console.error("❌ TEST 9 FAILED:", err);
  }

  // 10. Test DB operations
  try {
    console.log("[TEST 10] Testing db operations...");
    const testUser = await db.getUser('official@cyberguard.gov');
    console.log("Official User Found:", !!testUser);
  } catch (err: any) {
    console.error("❌ TEST 10 FAILED:", err);
  }

  console.log("=========================================");
  console.log("ALL TESTS COMPLETED!");
  console.log("=========================================");
}

testEverything();
