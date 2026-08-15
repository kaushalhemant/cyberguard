import { Breach, ThreatIntelligenceReport } from "../types";

function getNvidiaApiKey(): string {
  let key = process.env.NVIDIA_API_KEY || process.env.GEMINI_API_KEY || '';
  key = key.replace(/^["']|["']$/g, '').trim();
  if (key.startsWith('nvapi-')) return key;
  return '';
}

export function isNvidiaKeyAvailable(): boolean {
  return getNvidiaApiKey().length > 0;
}

async function callNvidiaChatCompletions(messages: any[], model: string = 'meta/llama-3.1-70b-instruct', responseFormatJson: boolean = false): Promise<string> {
  const apiKey = getNvidiaApiKey();
  if (!apiKey) throw new Error("No NVIDIA API key configured");

  const bodyObj: any = {
    model,
    messages,
    temperature: 0.6,
    max_tokens: 1500
  };

  if (responseFormatJson) {
    bodyObj.response_format = { type: "json_object" };
  }

  const response = await fetch('https://integrate.api.nvidia.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(bodyObj)
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`NVIDIA API Error (${response.status}): ${errorText}`);
  }

  const data: any = await response.json();
  const content = data.choices?.[0]?.message?.content || '';
  return content;
}

export async function generateNvidiaBreachReportSummary(
  targetEmail: string,
  breaches: Breach[],
  riskScore: number
): Promise<string> {
  const prompt = `
    You are CyberGuard AI powered by NVIDIA Llama-3.3, an elite cybersecurity incident responder. 
    Analyze the following data breach exposure report for email address: "${targetEmail}".
    User's Cyber Risk Score: ${riskScore}/100.
    
    Breaches found:
    ${JSON.stringify(
      breaches.map(b => ({
        title: b.Title,
        domain: b.Domain,
        date: b.BreachDate,
        description: b.Description,
        exposedData: b.DataClasses
      })),
      null,
      2
    )}
    
    Provide a professional, authoritative security assessment in markdown:
    1. **EXECUTIVE THREAT SUMMARY**
    2. **VULNERABILITY LEVEL & REASONING**
    3. **CRITICAL MITIGATION CHECKLIST**
  `;

  return await callNvidiaChatCompletions([
    { role: "system", content: "You are CyberGuard Security Engine powered by NVIDIA AI." },
    { role: "user", content: prompt }
  ]);
}

export async function generateNvidiaLinkThreatReport(url: string): Promise<{ riskScore: number; threats: string[]; aiSummary: string }> {
  const prompt = `
    Analyze target URL for security threats: "${url}"
    Evaluate for: Phishing, High-risk TLDs, Obfuscation, Scam patterns, Raw IP hosts.
    
    Respond STRICTLY with valid JSON object:
    {
      "riskScore": number (0-100),
      "threats": [string],
      "aiSummary": string (markdown report)
    }
  `;

  const text = await callNvidiaChatCompletions([
    { role: "system", content: "You are CyberGuard AI powered by NVIDIA NIM. Respond strictly in valid JSON." },
    { role: "user", content: prompt }
  ], 'meta/llama-3.1-70b-instruct', true);

  const parsed = JSON.parse(text || "{}");
  return {
    riskScore: typeof parsed.riskScore === 'number' ? parsed.riskScore : 20,
    threats: Array.isArray(parsed.threats) ? parsed.threats : ["Inspected via NVIDIA AI"],
    aiSummary: parsed.aiSummary || "Scan complete."
  };
}

export async function performNvidiaIntelligence(message: string, taskType: 'complex' | 'general' | 'fast'): Promise<string> {
  let systemInstruction = "You are CyberGuard AI, powered by NVIDIA NIM architecture. Provide expert cybersecurity guidance.";
  if (taskType === 'complex') {
    systemInstruction = "You are CyberGuard Principal Security Architect (NVIDIA Llama-3.3 70B Engine). Provide detailed policy, firewall, and architectural mitigation guidance.";
  }

  return await callNvidiaChatCompletions([
    { role: "system", content: systemInstruction },
    { role: "user", content: message }
  ]);
}

export async function generateNvidiaThreatIntelligenceReport(): Promise<ThreatIntelligenceReport> {
  const prompt = `
    Generate a real-time cybersecurity analysis of top global active alerts and trending phishing tactics.
    Respond strictly with valid JSON matching this schema:
    {
      "alerts": [
        {
          "id": string,
          "title": string,
          "severity": "critical" | "high" | "medium" | "low",
          "category": string,
          "description": string,
          "impact": string,
          "remediation": string,
          "timestamp": string
        }
      ],
      "phishingTactics": [
        {
          "id": string,
          "name": string,
          "trendLevel": "surging" | "stable" | "decreasing",
          "targetAudience": string,
          "description": string,
          "redFlags": [string],
          "prevention": string
        }
      ],
      "lastUpdated": string
    }
  `;

  const text = await callNvidiaChatCompletions([
    { role: "system", content: "You are CyberGuard Global Threat Intelligence Powered by NVIDIA AI. Output strictly valid JSON." },
    { role: "user", content: prompt }
  ], 'meta/llama-3.1-70b-instruct', true);

  const parsed = JSON.parse(text || "{}");
  return {
    alerts: Array.isArray(parsed.alerts) ? parsed.alerts : [],
    phishingTactics: Array.isArray(parsed.phishingTactics) ? parsed.phishingTactics : [],
    lastUpdated: parsed.lastUpdated || new Date().toISOString()
  };
}
