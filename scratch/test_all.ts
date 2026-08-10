import dotenv from 'dotenv';
dotenv.config();
import { GoogleGenAI } from '@google/genai';
import { scanUrl, scanEmail, scanImage, scanUnified } from '../src/server/scanners/unifiedScanner';
import { generateBreachReportSummary, generateLinkThreatReport, generateImageThreatReport, performSearchGrounding, performGeminiIntelligence } from '../src/server/cyberguardAI';

async function testAll() {
  console.log("=== 1. TESTING GEMINI API KEY ===");
  const apiKey = process.env.GEMINI_API_KEY || '';
  console.log("Key:", apiKey ? `${apiKey.substring(0, 8)}...` : 'EMPTY');

  try {
    const ai = new GoogleGenAI({ apiKey });
    console.log("Testing gemini-2.5-flash model...");
    const res = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: 'Hello CyberGuard',
    });
    console.log("Gemini 2.5 flash output:", res.text);
  } catch (err: any) {
    console.error("Gemini 2.5 flash ERROR:", err.message || err);
  }

  console.log("\n=== 2. TESTING SCANNERS ===");
  try {
    console.log("Testing URL Scanner (https://example.com)...");
    const urlReport = await scanUrl('https://example.com');
    console.log("URL Scan result riskScore:", urlReport.riskScore, "status:", urlReport.status);
  } catch (err: any) {
    console.error("URL Scan ERROR:", err);
  }

  try {
    console.log("Testing Email Scanner...");
    const emailReport = await scanEmail('test@example.com');
    console.log("Email Scan result riskScore:", emailReport.riskScore, "status:", emailReport.status);
  } catch (err: any) {
    console.error("Email Scan ERROR:", err);
  }

  try {
    console.log("Testing Link Threat Report (cyberguardAI)...");
    const linkReport = await generateLinkThreatReport('https://example.com');
    console.log("Link Threat Report riskScore:", linkReport.riskScore);
  } catch (err: any) {
    console.error("Link Threat Report ERROR:", err);
  }

  process.exit(0);
}

testAll().catch(e => {
  console.error("Fatal test error:", e);
  process.exit(1);
});
